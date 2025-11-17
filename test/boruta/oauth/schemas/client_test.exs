defmodule Boruta.Oauth.ClientTest do
  use ExUnit.Case

  alias Boruta.Oauth.Client

  describe "check_redirect_uri/2 with single wildcard (*)" do
    setup do
      client = %Client{
        id: "test-client",
        redirect_uris: ["https://*.example.com", "https://*.example.com/callback"]
      }

      {:ok, client: client}
    end

    test "matches valid DNS-safe subdomain", %{client: client} do
      assert :ok = Client.check_redirect_uri(client, "https://app.example.com")
      assert :ok = Client.check_redirect_uri(client, "https://api.example.com")
      assert :ok = Client.check_redirect_uri(client, "https://my-app.example.com")
    end

    test "matches DNS-safe subdomain with callback path", %{client: client} do
      assert :ok = Client.check_redirect_uri(client, "https://app.example.com/callback")
      assert :ok = Client.check_redirect_uri(client, "https://my-subdomain.example.com/callback")
    end

    test "rejects subdomain shorter than 3 characters", %{client: client} do
      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://ab.example.com")
    end

    test "rejects subdomain longer than 63 characters", %{client: client} do
      long_subdomain = String.duplicate("a", 64)

      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://#{long_subdomain}.example.com")
    end

    test "rejects subdomain with invalid characters", %{client: client} do
      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://app_underscore.example.com")

      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://app.subdomain.example.com")
    end

    test "rejects non-matching domain", %{client: client} do
      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://app.different.com")
    end
  end

  describe "check_redirect_uri/2 with double wildcard (**)" do
    setup do
      client = %Client{
        id: "test-client",
        redirect_uris: [
          "https://example.com/property/**",
          "https://example.com/tenant/**/callback"
        ]
      }

      {:ok, client: client}
    end

    test "matches short path segments", %{client: client} do
      assert :ok = Client.check_redirect_uri(client, "https://example.com/property/apartment")
      assert :ok = Client.check_redirect_uri(client, "https://example.com/property/house")
    end

    test "matches long path segments exceeding 63 characters", %{client: client} do
      long_slug = "extra-mega-super-long-slug-exceeding-by-far-the-sixty-three-character-limit"

      assert :ok = Client.check_redirect_uri(client, "https://example.com/property/#{long_slug}")
    end

    test "matches path with RFC 3986 unreserved characters", %{client: client} do
      assert :ok =
               Client.check_redirect_uri(
                 client,
                 "https://example.com/property/apartment-123_nice.place"
               )
    end

    test "matches path with percent-encoded characters", %{client: client} do
      assert :ok =
               Client.check_redirect_uri(
                 client,
                 "https://example.com/property/apartment%20with%20spaces"
               )
    end

    test "matches path with sub-delimiters and special characters", %{client: client} do
      assert :ok =
               Client.check_redirect_uri(
                 client,
                 "https://example.com/property/apartment!$&'()*+,;="
               )
    end

    test "matches path with colon and at-sign", %{client: client} do
      assert :ok =
               Client.check_redirect_uri(
                 client,
                 "https://example.com/property/apartment:v1@location"
               )
    end

    test "matches wildcard in middle of path", %{client: client} do
      assert :ok =
               Client.check_redirect_uri(
                 client,
                 "https://example.com/tenant/apartment-123/callback"
               )

      long_slug = String.duplicate("a", 100)

      assert :ok =
               Client.check_redirect_uri(
                 client,
                 "https://example.com/tenant/#{long_slug}/callback"
               )
    end

    test "rejects empty path segment", %{client: client} do
      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://example.com/property/")
    end

    test "rejects non-matching base path", %{client: client} do
      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://example.com/other/apartment")
    end

    test "rejects missing callback suffix", %{client: client} do
      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://example.com/tenant/apartment-123")
    end
  end

  describe "check_redirect_uri/2 with mixed wildcards" do
    setup do
      client = %Client{
        id: "test-client",
        redirect_uris: [
          "https://*.example.com/**",
          "https://app.example.com/property/**"
        ]
      }

      {:ok, client: client}
    end

    test "matches subdomain wildcard with path wildcard", %{client: client} do
      assert :ok = Client.check_redirect_uri(client, "https://my-app.example.com/any-path")

      assert :ok =
               Client.check_redirect_uri(
                 client,
                 "https://my-app.example.com/very-long-path-segment-that-exceeds-sixty-three-characters-easily"
               )
    end

    test "matches fixed subdomain with path wildcard", %{client: client} do
      assert :ok =
               Client.check_redirect_uri(client, "https://app.example.com/property/short-slug")

      long_slug = String.duplicate("x", 200)

      assert :ok =
               Client.check_redirect_uri(client, "https://app.example.com/property/#{long_slug}")
    end

    test "rejects invalid subdomain with valid path", %{client: client} do
      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://ab.example.com/any-path")
    end
  end

  describe "check_redirect_uri/2 with exact match (no wildcards)" do
    setup do
      client = %Client{
        id: "test-client",
        redirect_uris: ["https://example.com/callback", "https://app.example.com/oauth"]
      }

      {:ok, client: client}
    end

    test "matches exact URI", %{client: client} do
      assert :ok = Client.check_redirect_uri(client, "https://example.com/callback")
      assert :ok = Client.check_redirect_uri(client, "https://app.example.com/oauth")
    end

    test "rejects similar but not exact URI", %{client: client} do
      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://example.com/callback/extra")

      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://example.com/different")
    end
  end

  describe "check_redirect_uri/2 with special regex characters in URI" do
    setup do
      client = %Client{
        id: "test-client",
        redirect_uris: ["https://example.com/path?query=value", "https://example.com/path/**"]
      }

      {:ok, client: client}
    end

    test "matches URI with query parameters exactly", %{client: client} do
      assert :ok = Client.check_redirect_uri(client, "https://example.com/path?query=value")
    end

    test "rejects URI with different query parameters", %{client: client} do
      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://example.com/path?query=different")
    end

    test "matches wildcard path without being confused by special chars", %{client: client} do
      assert :ok = Client.check_redirect_uri(client, "https://example.com/path/segment")
    end
  end

  describe "check_redirect_uri/2 edge cases" do
    test "handles multiple redirect URIs with different patterns" do
      client = %Client{
        id: "test-client",
        redirect_uris: [
          "https://example.com/exact",
          "https://*.example.com",
          "https://example.com/path/**",
          "https://example.com/tenant/**/callback"
        ]
      }

      assert :ok = Client.check_redirect_uri(client, "https://example.com/exact")
      assert :ok = Client.check_redirect_uri(client, "https://subdomain.example.com")
      assert :ok = Client.check_redirect_uri(client, "https://example.com/path/any-segment")
      assert :ok = Client.check_redirect_uri(client, "https://example.com/tenant/123/callback")
    end

    test "rejects URI when no redirect URIs match" do
      client = %Client{
        id: "test-client",
        redirect_uris: ["https://example.com/exact"]
      }

      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://different.com/exact")
    end

    test "handles empty redirect URIs list" do
      client = %Client{
        id: "test-client",
        redirect_uris: []
      }

      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(client, "https://example.com/any")
    end
  end

  describe "wildcard replacement order" do
    test "replaces ** before * to avoid incorrect matching" do
      client = %Client{
        id: "test-client",
        redirect_uris: ["https://example.com/**"]
      }

      # Should match long paths with ** pattern
      long_path = String.duplicate("a", 100)
      assert :ok = Client.check_redirect_uri(client, "https://example.com/#{long_path}")
    end

    test "distinguishes between * and **" do
      client_with_single = %Client{
        id: "test-client-single",
        redirect_uris: ["https://*.example.com"]
      }

      client_with_double = %Client{
        id: "test-client-double",
        redirect_uris: ["https://example.com/**"]
      }

      # Single wildcard should work for DNS (3-63 chars)
      assert :ok = Client.check_redirect_uri(client_with_single, "https://app.example.com")

      long_subdomain = String.duplicate("a", 64)

      assert {:error, "Client redirect_uri do not match."} =
               Client.check_redirect_uri(
                 client_with_single,
                 "https://#{long_subdomain}.example.com"
               )

      # Double wildcard should work for long paths
      long_path = String.duplicate("a", 100)

      assert :ok =
               Client.check_redirect_uri(client_with_double, "https://example.com/#{long_path}")
    end
  end
end
