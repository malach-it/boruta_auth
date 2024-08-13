defmodule Boruta.CredentialsAdapter do
  @moduledoc """
  Encapsulate injected `Boruta.Openid.Credentials` adapter in context configuration
  """
  @behaviour Boruta.Openid.Credentials

  import Boruta.Config, only: [credentials: 0]

  def get_by(params), do: credentials().get_by(params)
  def create_credential(credential, token), do: credentials().create_credential(credential, token)
end
