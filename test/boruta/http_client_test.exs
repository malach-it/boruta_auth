defmodule Boruta.HttpClientTest do
  use ExUnit.Case

  alias Boruta.HttpClient
  alias Boruta.Support.TLSServer

  setup do
    {:ok, server} = TLSServer.start("pinned")

    on_exit(fn ->
      TLSServer.stop(server)
    end)

    {:ok, server}
  end

  test "performs a request when the server authority is pinned", %{
    url: url,
    trusted_authorities: trusted_authorities
  } do
    assert {:ok, %Finch.Response{status: 200, body: "pinned"}} =
             HttpClient.get(url, trusted_authorities)
  end

  test "rejects the request when a different authority is pinned", %{
    url: url,
    wrong_trusted_authorities: wrong_trusted_authorities
  } do
    assert {:error, "Host certificate is not trusted."} =
             HttpClient.get(url, wrong_trusted_authorities)
  end

  test "rejects the request when trusted authorities is empty", %{url: url} do
    assert {:error, "Client must configure trusted hosts or authorities for outbound requests."} =
             HttpClient.get(url, "")
  end

  test "rejects certificate authorities for a non-HTTPS URL", %{
    trusted_authorities: trusted_authorities
  } do
    assert {:error, "Certificate pinning requires HTTPS."} =
             HttpClient.get("http://localhost", trusted_authorities)
  end

  test "performs a request when host is trusted and certificate pinned", %{
    url: url,
    trusted_authorities: trusted_authorities
  } do
    assert {:ok, %Finch.Response{status: 200, body: "pinned"}} =
             HttpClient.get(url, trusted_authorities, ["localhost"])
  end

  test "normalizes trusted hosts", %{
    url: url,
    trusted_authorities: trusted_authorities
  } do
    assert {:ok, %Finch.Response{status: 200, body: "pinned"}} =
             HttpClient.get(url, trusted_authorities, [" LOCALHOST. "])
  end

  test "uses system authorities with only a trusted host configured", %{url: url} do
    assert {:error, "Host certificate is not trusted."} =
             HttpClient.get(url, "", ["localhost"])
  end

  test "adds the issuer host to trusted hosts", %{url: url} do
    set_issuer(url)

    assert {:error, "Host certificate is not trusted."} = HttpClient.get(url)
  end

  test "ignores an issuer that cannot be parsed", %{
    url: url,
    trusted_authorities: trusted_authorities
  } do
    set_issuer(:invalid)

    assert {:ok, %Finch.Response{status: 200, body: "pinned"}} =
             HttpClient.get(url, trusted_authorities)
  end

  test "rejects the request when the host is not trusted", %{
    url: url,
    trusted_authorities: trusted_authorities
  } do
    assert {:error, "Host is not trusted for outbound requests."} =
             HttpClient.get(url, trusted_authorities, ["example.com"])
  end

  test "rejects malformed request URLs", %{trusted_authorities: trusted_authorities} do
    assert {:error, "Could not parse outbound request host."} =
             HttpClient.get("not a URL", trusted_authorities, ["localhost"])
  end

  test "rejects unsupported request URL schemes", %{
    trusted_authorities: trusted_authorities
  } do
    assert {:error, "Could not parse outbound request host."} =
             HttpClient.get("ftp://localhost/resource", trusted_authorities, ["localhost"])
  end

  test "rejects invalid trusted host entries", %{
    url: url,
    trusted_authorities: trusted_authorities
  } do
    for trusted_hosts <- [[""], ["  .  "], [nil]] do
      assert {:error, "Invalid trusted hosts configuration."} =
               HttpClient.get(url, trusted_authorities, trusted_hosts)
    end
  end

  test "rejects a trusted hosts value that is not a list", %{
    url: url,
    trusted_authorities: trusted_authorities
  } do
    assert {:error, "Invalid trusted hosts configuration."} =
             HttpClient.get(url, trusted_authorities, "localhost")
  end

  test "rejects trusted authorities without PEM certificates", %{url: url} do
    assert {:error, "Trusted authorities must contain PEM certificates."} =
             HttpClient.get(url, "not a PEM certificate", ["localhost"])
  end

  test "performs a request when trusted hosts is empty but pinned", %{
    url: url,
    trusted_authorities: trusted_authorities
  } do
    assert {:ok,
            %Finch.Response{
              status: 200,
              body: "pinned"
            }} = HttpClient.get(url, trusted_authorities, [])
  end

  test "rejects the request when neither trusted hosts nor authorities are configured", %{
    url: url
  } do
    assert {:error, "Client must configure trusted hosts or authorities for outbound requests."} =
             HttpClient.get(url)
  end

  describe "get_cacerts/3" do
    test "uses system authorities for a matching trusted host", %{url: url} do
      assert {:ok, ^url, cacerts} = HttpClient.get_cacerts(url, ["localhost"], [])
      assert is_list(cacerts)
    end

    test "uses configured authorities for a matching trusted host", %{url: url} do
      authorities = [:certificate]

      assert {:ok, ^url, ^authorities} =
               HttpClient.get_cacerts(url, ["localhost"], authorities)
    end

    test "rejects a URL whose host is not in the normalized trusted hosts", %{url: url} do
      assert {:error, "Request URL host is not trusted."} =
               HttpClient.get_cacerts(url, ["example.com"], [])
    end

    test "rejects a malformed URL when trusted hosts are configured" do
      assert {:error, "Could not parse outbound request host."} =
               HttpClient.get_cacerts("not a URL", ["localhost"], [])
    end

    test "passes configured authorities through when host validation is disabled", %{url: url} do
      authorities = [:certificate]

      assert {:ok, ^url, ^authorities} = HttpClient.get_cacerts(url, [], authorities)
    end
  end

  defp set_issuer(issuer) do
    oauth_config = Application.get_env(:boruta, Boruta.Oauth)

    Application.put_env(
      :boruta,
      Boruta.Oauth,
      Keyword.put(oauth_config, :issuer, issuer)
    )

    on_exit(fn ->
      Application.put_env(:boruta, Boruta.Oauth, oauth_config)
    end)
  end
end
