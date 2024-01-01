defmodule Boruta.Openid.ApplicationMock do
  @moduledoc false
  @behaviour Boruta.Openid.Application

  @impl Boruta.Openid.Application
  def jwk_list(_conn, jwk_keys), do: {:jwk_list, jwk_keys}

  @impl Boruta.Openid.Application
  def userinfo_fetched(_conn, userinfo), do: {:userinfo_fetched, userinfo}

  @impl Boruta.Openid.Application
  def unauthorized(_conn, error), do: {:unauthorized, error}

  @impl Boruta.Openid.Application
  def client_registered(_conn, client), do: {:client_registered, client}

  @impl Boruta.Openid.Application
  def registration_failure(_conn, changeset), do: {:registration_failure, changeset}

  @impl Boruta.Openid.Application
  def credential_created(_conn, credential), do: {:credential_created, credential}

  @impl Boruta.Openid.Application
  def credential_failure(_conn, error), do: {:credential_failure, error}
end
