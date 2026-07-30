defmodule Boruta.Did.HttpTest do
  use ExUnit.Case, async: false

  alias Boruta.Did

  setup do
    bypass = Bypass.open()
    original_config = Application.get_env(:boruta, Boruta.Oauth, [])
    base_url = "http://localhost:#{bypass.port}"

    Application.put_env(
      :boruta,
      Boruta.Oauth,
      original_config
      |> Keyword.put(:ebsi_did_resolver_base_url, base_url)
      |> Keyword.put(:did_resolver_base_url, base_url)
      |> Keyword.put(:did_registrar_base_url, base_url)
      |> Keyword.put(:universal_did_auth, %{type: "bearer", token: "resolver-token"})
    )

    on_exit(fn -> Application.put_env(:boruta, Boruta.Oauth, original_config) end)

    {:ok, bypass: bypass}
  end

  describe "resolve/1 with an EBSI resolver" do
    test "extracts a wrapped DID document", %{bypass: bypass} do
      did = "did:ebsi:test"
      document = %{"id" => did}

      Bypass.expect_once(bypass, "GET", "/identifiers/:did", fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"didDocument" => document}))
      end)

      assert {:ok, ^document} = Did.resolve(did)
    end

    test "accepts an unwrapped DID document", %{bypass: bypass} do
      did = "did:ebsi:test"
      document = %{"id" => did, "verificationMethod" => []}

      Bypass.expect_once(bypass, "GET", "/identifiers/:did", fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 200, Jason.encode!(document))
      end)

      assert {:ok, ^document} = Did.resolve(did)
    end

    test "returns decoding and HTTP errors", %{bypass: bypass} do
      did = "did:ebsi:test"

      Bypass.expect_once(bypass, "GET", "/identifiers/:did", fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 200, "not-json")
      end)

      assert {:error, %Jason.DecodeError{}} = Did.resolve(did)

      Bypass.expect_once(bypass, "GET", "/identifiers/:did", fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 404, "not found")
      end)

      assert {:error, "not found"} = Did.resolve(did)
    end

    test "returns transport errors", %{bypass: bypass} do
      Bypass.down(bypass)

      assert {:error, error} = Did.resolve("did:ebsi:test")
      assert is_binary(error)
      assert error != ""
    end
  end

  describe "resolve/1 with a universal resolver" do
    test "returns the DID document and sends resolver authorization", %{bypass: bypass} do
      did = "did:example:test"
      document = %{"id" => did}

      Bypass.expect_once(bypass, "GET", "/identifiers/:did", fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer resolver-token"]
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"didDocument" => document}))
      end)

      assert {:ok, ^document} = Did.resolve(did)
    end

    test "returns HTTP, decoding, and unexpected response errors", %{bypass: bypass} do
      did = "did:example:test"

      Bypass.expect_once(bypass, "GET", "/identifiers/:did", fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 503, "unavailable")
      end)

      assert {:error, "unavailable"} = Did.resolve(did)

      Bypass.expect_once(bypass, "GET", "/identifiers/:did", fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 200, "not-json")
      end)

      assert {:error, decode_error} = Did.resolve(did)
      assert decode_error =~ "Jason.DecodeError"

      Bypass.expect_once(bypass, "GET", "/identifiers/:did", fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"unexpected" => true}))
      end)

      assert {:error, ~s(Invalid resolver response: "%{"unexpected" => true}")} =
               Did.resolve(did)
    end
  end

  describe "create/2 with a universal registrar" do
    test "creates a DID and resolves its public JWK", %{bypass: bypass} do
      did = "did:example:created"
      jwk = %{"kty" => "OKP", "crv" => "Ed25519", "x" => "public-key"}

      Bypass.expect_once(bypass, "POST", "/create", fn conn ->
        assert conn.query_string == "method=key"
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer resolver-token"]
        assert Plug.Conn.get_req_header(conn, "content-type") == ["application/json"]

        {:ok, body, conn} = Plug.Conn.read_body(conn)
        assert Jason.decode!(body)["options"]["keyType"] == "Ed25519"

        Plug.Conn.resp(conn, 201, Jason.encode!(%{"didState" => %{"did" => did}}))
      end)

      Bypass.expect_once(bypass, "GET", "/identifiers/:did", fn conn ->
        assert conn.request_path == "/identifiers/#{encoded(did)}"
        document = %{"verificationMethod" => [%{"publicKeyJwk" => jwk}]}
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"didDocument" => document}))
      end)

      assert {:ok, ^did, ^jwk} = Did.create("key")
    end

    test "returns a stable error when registration fails", %{bypass: bypass} do
      Bypass.expect_once(bypass, "POST", "/create", fn conn ->
        Plug.Conn.resp(conn, 400, "invalid")
      end)

      assert {:error, "Could not create did."} = Did.create("key")
    end
  end

  defp encoded(value), do: URI.encode(value, &URI.char_unreserved?/1)
end
