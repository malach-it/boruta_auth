defmodule Boruta.ScopesAdapter do
  @moduledoc """
  Encapsulate injected scopes adapter in context configuration.
  """
  @behaviour Boruta.Oauth.Scopes

  import Boruta.Config, only: [scopes: 0]

  def public, do: scopes().public()
end
