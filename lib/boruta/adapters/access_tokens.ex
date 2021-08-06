defmodule Boruta.AccessTokensAdapter do
  @moduledoc """
  Encapsulate injected access_tokens adapter in context configuration.
  """

  @behaviour Boruta.Oauth.AccessTokens

  import Boruta.Config, only: [access_tokens: 0]

  defdelegate get_by(params), to: access_tokens()
  defdelegate create(params, opts), to: access_tokens()
  defdelegate revoke(token), to: access_tokens()
end
