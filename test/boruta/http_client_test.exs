defmodule Boruta.HttpClientTest do
  use ExUnit.Case

  import Plug.Conn

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

  test "performs a POST request with body, headers, and query parameters" do
    request_handler = fn conn ->
      {:ok, body, conn} = read_body(conn)

      response =
        Jason.encode!(%{
          method: conn.method,
          path: conn.request_path,
          query: conn.query_string,
          body: body,
          content_type: get_req_header(conn, "content-type")
        })

      send_resp(conn, 200, response)
    end

    {:ok, post_server} = TLSServer.start("unused", request_handler: request_handler)
    on_exit(fn -> TLSServer.stop(post_server) end)

    assert {:ok, %Finch.Response{status: 200, body: response}} =
             HttpClient.post(
               "#{post_server.url}/callback?state=expected",
               ~s({"code":"value"}),
               [{"content-type", "application/json"}],
               post_server.trusted_authorities
             )

    assert Jason.decode!(response) == %{
             "method" => "POST",
             "path" => "/callback",
             "query" => "state=expected",
             "body" => ~s({"code":"value"}),
             "content_type" => ["application/json"]
           }
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

  test "uses system authorities with only a trusted host configured", %{url: url} do
    assert {:error, "Host certificate is not trusted."} =
             HttpClient.get(url, "", ["localhost"])
  end

  test "adds the issuer host to trusted hosts", %{url: url} do
    oauth_config = Application.get_env(:boruta, Boruta.Oauth)

    Application.put_env(
      :boruta,
      Boruta.Oauth,
      Keyword.put(oauth_config, :issuer, url)
    )

    on_exit(fn ->
      Application.put_env(:boruta, Boruta.Oauth, oauth_config)
    end)

    assert {:error, "Host certificate is not trusted."} = HttpClient.get(url)
  end

  test "trusts DID service hosts by default" do
    for host <- ["api.godiddy.com", "api-conformance.ebsi.eu"] do
      assert {:error, "Certificate pinning requires HTTPS."} =
               HttpClient.get("http://#{host}/identifiers/did:example:test")

      assert {:error, "Certificate pinning requires HTTPS."} =
               HttpClient.post("http://#{host}/create", "{}")
    end
  end

  test "trusts hosts from the configured DID service URLs" do
    oauth_config = Application.get_env(:boruta, Boruta.Oauth)

    service_keys = [
      :ebsi_did_resolver_base_url,
      :did_resolver_base_url,
      :did_registrar_base_url
    ]

    configured_hosts =
      service_keys
      |> Enum.with_index()
      |> Enum.map(fn {key, index} ->
        host = "did-service-#{index}.example.test"
        {key, "https://#{host}/service", host}
      end)

    overrides = Enum.map(configured_hosts, fn {key, url, _host} -> {key, url} end)
    Application.put_env(:boruta, Boruta.Oauth, Keyword.merge(oauth_config, overrides))
    on_exit(fn -> Application.put_env(:boruta, Boruta.Oauth, oauth_config) end)

    for {_key, _url, host} <- configured_hosts do
      assert {:error, "Certificate pinning requires HTTPS."} = HttpClient.get("http://#{host}")
    end

    assert {:error, "Client must configure trusted hosts or authorities for outbound requests."} =
             HttpClient.get("http://api.godiddy.com")
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
    assert {:error, "Client must configure trusted hosts or authorities for outbound requests."} =
             HttpClient.get(url)
  end
end
