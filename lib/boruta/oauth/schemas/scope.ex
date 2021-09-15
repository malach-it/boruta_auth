defmodule Boruta.Oauth.Scope do
  @moduledoc """
  Schema defining an independent OAuth scope
  """
  defstruct id: nil, name: nil, label: nil, public: nil

  @type t :: %__MODULE__{
          id: any(),
          label: String.t(),
          name: String.t(),
          public: boolean()
        }

  @doc """
  Splits an OAuth scope string into individual scopes as string
  ## Examples
      iex> scope("a:scope another:scope")
      ["a:scope", "another:scope"]
  """
  @spec split(oauth_scope :: String.t() | nil) :: list(String.t())
  def split(nil), do: []

  def split(scope) do
    Enum.filter(
      String.split(scope, " "),
      # remove empty strings
      fn scope -> scope != "" end
    )
  end

  @doc """
  Determines if artifact is authorized to access given scope.
  """
  @spec authorized?(
          against :: List | Boruta.Oauth.Token.t() | Boruta.Oauth.Client.t(),
          scope :: String.t()
        ) :: boolean()
  @spec authorized?(
          against :: List | Boruta.Oauth.Token.t() | Boruta.Oauth.Client.t(),
          scope :: String.t(),
          public_scopes :: list()
        ) :: boolean()
  defdelegate authorized?(against, scope, public_scopes \\ []), to: __MODULE__.Authorize
end
