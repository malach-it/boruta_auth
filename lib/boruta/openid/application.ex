defmodule Boruta.Openid.Application do
  @moduledoc """
  Implement this behaviour in the application layer of your OpenID Connect provider.
  This behaviour gives all callbacks triggered invoking `Boruta.Openid` module functions.

  > __Note__: This behaviour is split into `Boruta.Openid.JwksApplication` and `Boruta.Openid.UserinfoApplication` providing utilities to implement the different OpenID Connect endpoints independently.
  """

  @type direct_post_params :: %{
          code_id: String.t(),
          id_token: nil | String.t()
        }

  @doc """
  This function will be triggered in case of success invoking `Boruta.Openid.jwks/2`
  """
  @callback jwk_list(conn :: Plug.Conn.t(), jwk_keys :: list(%JOSE.JWK{})) ::
              any()
  @doc """
  This function will be triggered in case of success invoking `Boruta.Openid.userinfo/2`
  """
  @callback userinfo_fetched(conn :: Plug.Conn.t(), userinfo :: map()) ::
              any()
  @doc """
  This function will be triggered when request is unauthorized invoking `Boruta.Openid.userinfo/2`
  """
  @callback unauthorized(conn :: Plug.Conn.t(), error :: Boruta.Oauth.Error.t()) ::
              any()
  @doc """
  This function will be triggered when request is unauthorized invoking `Boruta.Openid.register_client/3`
  """
  @callback client_registered(conn :: Plug.Conn.t(), client :: Boruta.Oauth.Client.t()) ::
              any()
  @doc """
  This function will be triggered when request is unauthorized invoking `Boruta.Openid.register_client/3`
  """
  @callback registration_failure(conn :: Plug.Conn.t(), changeset :: Ecto.Changeset.t()) ::
              any()
  @doc """
  This function will be triggered in case of success invoking `Boruta.Openid.credential/3`
  """
  @callback credential_created(
              conn :: Plug.Conn.t(),
              credential :: Boruta.Openid.CredentialResponse.t()
            ) ::
              any()
  @doc """
  This function will be triggered in case of failure invoking `Boruta.Openid.credential/3`
  """
  @callback credential_failure(conn :: Plug.Conn.t(), error :: Boruta.Oauth.Error.t()) ::
              any()
  @callback direct_post_success(
              conn :: Plug.Conn.t() | map(),
              response :: Boruta.Openid.DirectPostResponse.t()
            ) :: any()
  @callback code_not_found(conn :: Plug.Conn.t()) :: any()
  @callback authentication_failure(conn :: Plug.Conn.t(), error :: Boruta.Oauth.Error.t()) ::
              any()
end
