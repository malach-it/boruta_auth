defmodule Boruta.ScopesAdapter do
  @moduledoc """
  Encapsulate injected scopes adapter in context configuration.
  """
  @behaviour Boruta.Oauth.Scopes

  import Boruta.Config, only: [scopes: 0]

  defdelegate public, to: scopes()
end
