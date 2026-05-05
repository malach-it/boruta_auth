defmodule Boruta.Oauth.Authorization.ResourceTest do
  use ExUnit.Case

  alias Boruta.Oauth.Authorization.Resource
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Error

  describe "authorize/2" do
    test "accepts nil resources" do
      assert Resource.authorize(nil, %Client{id: "client"}) == {:ok, nil}
    end

    test "accepts absolute URI resources" do
      assert Resource.authorize("https://mcp.example.com/messages?tenant=1", %Client{id: "client"}) ==
               {:ok, "https://mcp.example.com/messages?tenant=1"}
    end

    test "accepts URN resources" do
      assert Resource.authorize("urn:example:mcp", %Client{id: "client"}) ==
               {:ok, "urn:example:mcp"}
    end

    test "rejects resources with fragments" do
      assert {:error,
              %Error{
                status: :bad_request,
                error: :invalid_target,
                error_description:
                  "Requested resource must be an absolute URI without a fragment."
              }} =
               Resource.authorize("https://mcp.example.com#tools", %Client{id: "client"})
    end

    test "rejects relative resources" do
      assert {:error,
              %Error{
                status: :bad_request,
                error: :invalid_target,
                error_description:
                  "Requested resource must be an absolute URI without a fragment."
              }} = Resource.authorize("/messages", %Client{id: "client"})
    end

    test "rejects malformed resources" do
      assert {:error,
              %Error{
                status: :bad_request,
                error: :invalid_target,
                error_description:
                  "Requested resource must be an absolute URI without a fragment."
              }} = Resource.authorize("https://exa mple.com", %Client{id: "client"})
    end

    test "rejects resources with invalid percent encoding" do
      assert {:error,
              %Error{
                status: :bad_request,
                error: :invalid_target,
                error_description:
                  "Requested resource must be an absolute URI without a fragment."
              }} = Resource.authorize("https://mcp.example.com/%ZZ", %Client{id: "client"})
    end

    test "rejects resources with characters outside the URI grammar" do
      assert {:error,
              %Error{
                status: :bad_request,
                error: :invalid_target,
                error_description:
                  "Requested resource must be an absolute URI without a fragment."
              }} = Resource.authorize("https://mcp.example.com/{tenant}", %Client{id: "client"})
    end

    test "does not restrict resources when client does not configure an allowlist" do
      assert Resource.authorize("https://mcp.example.com", %Client{
               id: "client",
               authorized_resources: []
             }) == {:ok, "https://mcp.example.com"}
    end

    test "accepts resources present in the client allowlist" do
      assert Resource.authorize("https://mcp.example.com", %Client{
               id: "client",
               authorized_resources: ["https://mcp.example.com"]
             }) == {:ok, "https://mcp.example.com"}
    end

    test "rejects resources missing from the client allowlist" do
      assert {:error,
              %Error{
                status: :bad_request,
                error: :invalid_target,
                error_description: "Requested resource is not authorized for this client."
              }} =
               Resource.authorize("https://other.example.com", %Client{
                 id: "client",
                 authorized_resources: ["https://mcp.example.com"]
               })
    end
  end

  describe "authorize/3" do
    test "uses the originally authorized resource when token request omits resource" do
      assert Resource.authorize(nil, %Client{id: "client"}, "https://mcp.example.com") ==
               {:ok, "https://mcp.example.com"}
    end

    test "does not add a requested resource when the original grant has no resource" do
      assert {:error,
              %Error{
                status: :bad_request,
                error: :invalid_target,
                error_description: "Requested resource is not authorized for this token."
              }} =
               Resource.authorize(
                 "https://mcp.example.com",
                 %Client{id: "client"},
                 nil
               )
    end

    test "rejects resource escalation from an authorization grant" do
      assert {:error,
              %Error{
                status: :bad_request,
                error: :invalid_target,
                error_description: "Requested resource is not authorized for this token."
              }} =
               Resource.authorize(
                 "https://other.example.com",
                 %Client{id: "client"},
                 "https://mcp.example.com"
               )
    end
  end
end
