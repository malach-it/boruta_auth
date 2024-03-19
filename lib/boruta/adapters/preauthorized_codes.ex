defmodule Boruta.PreauthorizedCodesAdapter do
  @moduledoc """
  Encapsulate injected `Boruta.Oauth.Codes` adapter in context configuration
  """

  @behaviour Boruta.Openid.PreauthorizedCodes

  import Boruta.Config, only: [preauthorized_codes: 0]

  # def get_by(params), do: preauthorized_codes().get_by(params)
  def create(params), do: preauthorized_codes().create(params)
  # def revoke(code), do: preauthorized_codes().revoke(code)
end
