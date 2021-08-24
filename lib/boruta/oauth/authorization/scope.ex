defmodule Boruta.Oauth.Authorization.Scope do
  @moduledoc """
  Scope authorization
  """

  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.Token
  alias Boruta.ScopesAdapter

  @doc """
  Authorize the given scope according to the given client.

  ## Examples
      iex> authorize(%{scope: "scope", client: %Client{...}})
      {:ok, "scope"}
  """
  @spec authorize(
          params :: [
            scope: String.t(),
            against: %{
              optional(:client) => %Client{},
              optional(:resource_owner) => struct(),
              optional(:token) => %Token{}
            }
          ]
        ) ::
          {:ok, scope :: String.t()}
          | {:error, Error.t()}
  def authorize(scope: nil, against: _against), do: {:ok, ""}

  def authorize(scope: "" <> scope, against: against) do
    scopes = Scope.split(scope)

    public_scopes =
      ScopesAdapter.public()
      |> Enum.map(fn scope -> scope.name end)

    against = Map.put(against, :public, public_scopes)

    authorized_scopes = authorized_scopes(scopes, against, [])

    case Enum.empty?(scopes -- authorized_scopes) do
      true ->
        authorized_scope = Enum.join(authorized_scopes, " ")
        {:ok, authorized_scope}

      false ->
        {:error,
         %Boruta.Oauth.Error{
           error: :invalid_scope,
           error_description: "Given scopes are unknown or unauthorized.",
           status: :bad_request
         }}
    end
  end

  defp authorized_scopes([], _against, authorized_scopes), do: authorized_scopes

  defp authorized_scopes(scopes, against, authorized_scopes) do
    [current_scope | scopes] = scopes

    case authorized?(current_scope, against) do
      true ->
        authorized_scopes(scopes, against, authorized_scopes ++ [current_scope])

      false ->
        authorized_scopes(scopes, against, authorized_scopes)
    end
  end

  defp authorized?(scope, against) do
    against
    |> Enum.reduce(false, fn
      {:token, schema}, _acc ->
        Scope.authorized?(schema, scope)

      {_type, schema}, acc ->
        acc || Scope.authorized?(schema, scope)
    end)
  end
end
