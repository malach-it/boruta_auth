defmodule Boruta.Oauth.Scope do
  @moduledoc """
  Schema defining an independent OAuth scope
  """

  @enforce_keys [:name]
  defstruct id: nil, name: nil, label: nil, public: nil

  @type t :: %__MODULE__{
          id: any() | nil,
          label: String.t() | nil,
          name: String.t(),
          public: boolean() | nil
        }
  @type raw :: String.t()

  @doc """
  Splits an OAuth scope string into individual scopes as string
  ## Examples
      iex> scope("a:scope another:scope")
      ["a:scope", "another:scope"]
  """
  @spec split(oauth_scope :: String.t() | nil) :: list(raw())
  def split(nil), do: []

  def split(scope) do
    String.split(scope, " ", trim: true)
  end

  @spec openid() :: t()
  def openid do
    %__MODULE__{
      label: "OpenID Connect reserved scope",
      name: "openid",
      public: true
    }
  end

  @spec contains_openid?(oauth_scope :: String.t()) :: boolean()
  def contains_openid?(scope) when is_binary(scope) do
    String.match?(scope, ~r/#{openid().name}/)
  end

  def contains_openid?(_scope), do: false

  @spec authorized?(
          against :: List | Boruta.Oauth.Token.t() | Boruta.Oauth.Client.t(),
          scope :: String.t()
        ) :: boolean()
  @spec authorized?(
          against :: List | Boruta.Oauth.Token.t() | Boruta.Oauth.Client.t(),
          scope :: String.t(),
          public_scopes :: list()
        ) :: boolean()
  defdelegate authorized?(against, scope), to: __MODULE__.Authorize
  defdelegate authorized?(against, scope, public_scopes), to: __MODULE__.Authorize
end
