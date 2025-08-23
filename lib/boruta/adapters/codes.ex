defmodule Boruta.CodesAdapter do
  @moduledoc """
  Encapsulate injected `Boruta.Oauth.Codes` adapter in context configuration
  """

  @behaviour Boruta.Oauth.Codes

  import Boruta.Config, only: [codes: 0]

  def get_by(params), do: codes().get_by(params)
  def create(params), do: codes().create(params)
  def revoke(code), do: codes().revoke(code)
  def revoke_previous_token(code), do: codes().revoke_previous_token(code)
  def update_sub(code, sub, metadata_policy), do: codes().update_sub(code, sub, metadata_policy)
  def code_chain(code), do: codes().code_chain(code)
end
