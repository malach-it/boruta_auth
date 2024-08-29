defmodule Boruta.Openid.PreauthorizedCodes do
  @moduledoc """
  Preauthorized code context
  """

  @callback create(params :: %{
    :client => Boruta.Oauth.Client.t(),
    :sub => String.t(),
    :redirect_uri => String.t(),
    :scope => String.t(),
    :state => String.t(),
    :resource_owner => Boruta.Oauth.ResourceOwner.t()
  }) :: preauthorized_code :: Boruta.Oauth.Token.t() | {:error, reason :: term()}
end
