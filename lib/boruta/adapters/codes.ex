defmodule Boruta.CodesAdapter do
  @moduledoc """
  Encapsulate injected `Boruta.Oauth.Codes` adapter in context configuration
  """

  @behaviour Boruta.Oauth.Codes

  import Boruta.Config, only: [codes: 0]

  def get_by(params), do: codes().get_by(params)
  def create(params), do: codes().create(params)
  def revoke(code), do: codes().revoke(code)
end
