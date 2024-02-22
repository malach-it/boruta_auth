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

  @impl Boruta.Openid.Application
  def direct_post_success(_conn, response), do: {:direct_post_success, response}

  @impl Boruta.Openid.Application
  def code_not_found(_conn), do: {:code_not_found}

  @impl Boruta.Openid.Application
  def authentication_failure(_conn, error), do: {:authentication_failure, error}
end
