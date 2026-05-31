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
    assert {:error, "Client do not trust authorities for outbound requests."} =
             HttpClient.get(url, "")
  end
end
