defmodule Boruta.Ecto.ScopesTest do
  use Boruta.DataCase

  alias Boruta.Ecto.Admin
  alias Boruta.Ecto.Scopes
  alias Boruta.Oauth

  describe "all/0" do
    test "returns scopes from cache" do
      {:ok, scope_a} = Admin.create_scope(%{name: "a"})
      {:ok, scope_b} = Admin.create_scope(%{name: "b"})

      scopes =
        [scope_a, scope_b]
        |> Enum.map(fn scope -> struct(Oauth.Scope, Map.from_struct(scope)) end)
        |> Enum.sort()

      assert Enum.sort(Scopes.all()) == scopes
      assert Enum.sort(Scopes.all()) == scopes

      {:ok, scope_c} = Admin.create_scope(%{name: "c"})
      scopes = [struct(Oauth.Scope, Map.from_struct(scope_c)) | scopes] |> Enum.sort()

      assert Enum.sort(Scopes.all()) == scopes
      assert Enum.sort(Scopes.all()) == scopes
    end
  end
end
