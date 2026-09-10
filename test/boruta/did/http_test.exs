defmodule Boruta.Did.HttpTest do
  use ExUnit.Case, async: false

  alias Boruta.Did
  alias Boruta.Oauth.Client
  alias Boruta.Support.TLSServer

  defmodule Clients do
    @moduledoc false

    def public!, do: Application.fetch_env!(:boruta, __MODULE__)
  end

  setup do
    {:ok, expectations} = Agent.start_link(fn -> [] end)

    request_handler = fn conn ->
      case Agent.get_and_update(expectations, fn
             [expectation | expectations] -> {expectation, expectations}
             [] -> {nil, []}
           end) do
        nil -> Plug.Conn.send_resp(conn, 500, "Unexpected request")
        expectation -> expectation.(conn)
      end
    end

    {:ok, server} = TLSServer.start("unused", request_handler: request_handler)
    original_config = Application.get_env(:boruta, Boruta.Oauth, [])
    original_client = Application.get_env(:boruta, Clients)

    contexts =
      original_config
      |> Keyword.fetch!(:contexts)
      |> Keyword.put(:clients, Clients)

    Application.put_env(
      :boruta,
      Boruta.Oauth,
      original_config
      |> Keyword.put(:contexts, contexts)
      |> Keyword.put(:ebsi_did_resolver_base_url, server.url)
      |> Keyword.put(:did_resolver_base_url, server.url)
      |> Keyword.put(:universal_did_auth, %{type: "bearer", token: "resolver-token"})
    )

    Application.put_env(
      :boruta,
      Clients,
      %Client{
        id: "public",
        trusted_authorities: server.trusted_authorities,
        trusted_hosts: ["localhost"]
      }
    )

    on_exit(fn ->
      TLSServer.stop(server)
      Application.put_env(:boruta, Boruta.Oauth, original_config)

      if original_client do
        Application.put_env(:boruta, Clients, original_client)
      else
        Application.delete_env(:boruta, Clients)
      end
    end)

    {:ok, server: server, expectations: expectations}
  end

  describe "resolve/1 with an EBSI resolver" do
    test "extracts a wrapped DID document", %{expectations: expectations} do
      did = "did:ebsi:test"
      document = %{"id" => did}

      expect(expectations, fn conn ->
        assert conn.method == "GET"
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"didDocument" => document}))
      end)

      assert {:ok, ^document} = Did.resolve(did)
    end

    test "accepts an unwrapped DID document", %{expectations: expectations} do
      did = "did:ebsi:test"
      document = %{"id" => did, "verificationMethod" => []}

      expect(expectations, fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 200, Jason.encode!(document))
      end)

      assert {:ok, ^document} = Did.resolve(did)
    end

    test "returns decoding and HTTP errors", %{expectations: expectations} do
      did = "did:ebsi:test"

      expect(expectations, fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 200, "not-json")
      end)

      assert {:error, %Jason.DecodeError{}} = Did.resolve(did)

      expect(expectations, fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 404, "not found")
      end)

      assert {:error, "not found"} = Did.resolve(did)
    end

    test "returns transport errors", %{server: server} do
      TLSServer.stop(server)

      assert {:error, error} = Did.resolve("did:ebsi:test")
      assert is_binary(error)
      assert error != ""
    end
  end

  describe "resolve/1 with a universal resolver" do
    test "returns the DID document and sends resolver authorization", %{
      expectations: expectations
    } do
      did = "did:example:test"
      document = %{"id" => did}

      expect(expectations, fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer resolver-token"]
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"didDocument" => document}))
      end)

      assert {:ok, ^document} = Did.resolve(did)
    end

    test "returns HTTP, decoding, and unexpected response errors", %{
      expectations: expectations
    } do
      did = "did:example:test"

      expect(expectations, fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 503, "unavailable")
      end)

      assert {:error, "unavailable"} = Did.resolve(did)

      expect(expectations, fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 200, "not-json")
      end)

      assert {:error, decode_error} = Did.resolve(did)
      assert decode_error =~ "Jason.DecodeError"

      expect(expectations, fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"unexpected" => true}))
      end)

      assert {:error, ~s(Invalid resolver response: "%{"unexpected" => true}")} =
               Did.resolve(did)
    end
  end

  defp expect(expectations, expectation) do
    Agent.update(expectations, &(&1 ++ [expectation]))
  end

  defp encoded(value), do: URI.encode(value, &URI.char_unreserved?/1)
end
