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
    assert {:error, "Host certificate is not trusted."} =
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

  test "uses system authorities with only a trusted host configured", %{url: url} do
    assert {:error, "Host certificate is not trusted."} =
             HttpClient.get(url, "", ["localhost"])
  end

  test "rejects the request when the host is not trusted", %{
    url: url,
    trusted_authorities: trusted_authorities
  } do
    assert {:error, "Host is not trusted for outbound requests."} =
             HttpClient.get(url, trusted_authorities, ["example.com"])
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
    assert {:error, "Host certificate is not trusted."} =
             HttpClient.get(url)
  end
end
