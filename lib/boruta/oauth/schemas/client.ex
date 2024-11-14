defmodule Boruta.Oauth.Client do
  @moduledoc """
  OAuth client schema and utilities
  """

  defmodule Token do
    @moduledoc false

    use Joken.Config

    def token_config, do: %{}
  end

  @enforce_keys [:id]
  defstruct id: nil,
            public_client_id: nil,
            name: nil,
            secret: nil,
            confidential: nil,
            authorize_scope: nil,
            authorized_scopes: [],
            enforce_dpop: nil,
            enforce_tx_code: nil,
            redirect_uris: [],
            supported_grant_types: [],
            access_token_ttl: nil,
            id_token_ttl: nil,
            authorization_code_ttl: nil,
            authorization_request_ttl: nil,
            refresh_token_ttl: nil,
            pkce: nil,
            public_refresh_token: nil,
            public_revoke: nil,
            id_token_signature_alg: nil,
            id_token_kid: nil,
            userinfo_signed_response_alg: nil,
            token_endpoint_auth_methods: nil,
            token_endpoint_jwt_auth_alg: nil,
            jwt_public_key: nil,
            jwks_uri: nil,
            public_key: nil,
            private_key: nil,
            did: nil,
            logo_uri: nil,
            response_mode: nil,
            metadata: %{}

  @type t :: %__MODULE__{
          id: any(),
          public_client_id: String.t() | nil,
          secret: String.t(),
          confidential: boolean(),
          name: String.t(),
          authorize_scope: boolean(),
          authorized_scopes: list(Boruta.Oauth.Scope.t()),
          enforce_dpop: boolean(),
          enforce_tx_code: boolean(),
          redirect_uris: list(String.t()),
          supported_grant_types: list(String.t()),
          access_token_ttl: integer(),
          id_token_ttl: integer(),
          authorization_code_ttl: integer(),
          authorization_request_ttl: integer(),
          refresh_token_ttl: integer(),
          pkce: boolean(),
          public_refresh_token: boolean(),
          public_revoke: boolean(),
          id_token_signature_alg: String.t(),
          id_token_kid: String.t() | nil,
          userinfo_signed_response_alg: String.t() | nil,
          token_endpoint_auth_methods: list(String.t()),
          token_endpoint_jwt_auth_alg: String.t(),
          jwt_public_key: String.t(),
          jwks_uri: String.t() | nil,
          public_key: String.t(),
          private_key: String.t(),
          did: String.t() | nil,
          logo_uri: String.t() | nil,
          response_mode: String.t(),
          metadata: map()
        }

  @wallet_grant_types [
    "id_token",
    "vp_token",
    "authorization_code"
  ]

  @grant_types Enum.uniq(
                 [
                   "client_credentials",
                   "password",
                   "authorization_code",
                   "preauthorized_code",
                   "refresh_token",
                   "implicit",
                   "revoke",
                   "introspect"
                 ] ++ @wallet_grant_types
               )

  @doc """
  Returns grant types supported by the server. `Boruta.Oauth.Client` `supported_grant_types` attribute may be a subset of them.
  """
  @spec grant_types() :: grant_types :: list(String.t())
  def grant_types, do: @grant_types

  @spec grant_type_supported?(client :: t(), grant_type :: String.t()) :: boolean()
  def grant_type_supported?(%__MODULE__{supported_grant_types: supported_grant_types}, "code") do
    Enum.member?(supported_grant_types, "authorization_code")
  end

  def grant_type_supported?(
        %__MODULE__{supported_grant_types: supported_grant_types},
        "preauthorization_code"
      ) do
    Enum.member?(supported_grant_types, "preauthorized_code")
  end

  def grant_type_supported?(%__MODULE__{supported_grant_types: supported_grant_types}, grant_type) do
    Enum.member?(supported_grant_types, grant_type)
  end

  @doc """
  Returns wallet grant types supported by the server. `Boruta.Oauth.Client` `supported_grant_types` attribute may be a subset of them.
  """
  @spec wallet_grant_types() :: grant_types :: list(String.t())
  def wallet_grant_types, do: @wallet_grant_types

  @spec wallet_grant_type_supported?(client :: t(), grant_type :: String.t()) :: boolean()
  def wallet_grant_type_supported?(
        %__MODULE__{supported_grant_types: supported_grant_types},
        grant_type
      )
      when grant_type in @wallet_grant_types do
    Enum.member?(supported_grant_types, grant_type)
  end

  def wallet_grant_type_supported?(_client, _grant_type), do: false

  @spec check_secret(client :: t(), secret :: String.t()) :: :ok | {:error, String.t()}
  def check_secret(%__MODULE__{secret: secret}, secret), do: :ok
  def check_secret(_client, _secret), do: {:error, "Invalid client secret."}

  @spec check_redirect_uri(client :: t(), redirect_uri :: String.t()) ::
          :ok | {:error, String.t()}
  def check_redirect_uri(%__MODULE__{redirect_uris: client_redirect_uris}, redirect_uri) do
    case Enum.any?(client_redirect_uris, fn client_redirect_uri ->
           redirect_uri_regex =
             client_redirect_uri
             |> Regex.escape()
             |> String.replace("\\*", "([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9])")

           redirect_uri_regex =
             "^#{redirect_uri_regex}$"
             |> Regex.compile!()

           Regex.match?(redirect_uri_regex, redirect_uri)
         end) do
      true -> :ok
      false -> {:error, "Client redirect_uri do not match."}
    end
  end

  @spec should_check_secret?(client :: t(), grant_type :: String.t()) :: boolean()
  def should_check_secret?(_client, grant_type)
      when grant_type in ["implicit", "code", "preauthorized_code"],
      do: false

  def should_check_secret?(client, grant_type) when grant_type in ["refresh_token", "revoke"] do
    not apply(__MODULE__, :"public_#{grant_type}?", [client])
  end

  def should_check_secret?(%__MODULE__{public_client_id: "" <> _client_id}, _grant_type),
    do: false

  def should_check_secret?(%__MODULE__{confidential: true}, _grant_type), do: true

  def should_check_secret?(_client, grant_type)
      when grant_type in ["client_credentials", "introspect"],
      do: true

  def should_check_secret?(%__MODULE__{confidential: false}, _grant_type), do: false

  @spec public_refresh_token?(client :: t()) :: boolean()
  def public_refresh_token?(%__MODULE__{public_refresh_token: public_refresh_token}) do
    public_refresh_token
  end

  @spec public_revoke?(client :: t()) :: boolean()
  def public_revoke?(%__MODULE__{public_revoke: public_revoke}) do
    public_revoke
  end

  @spec public?(client :: t()) :: boolean()
  def public?(%__MODULE__{public_client_id: public_client_id}) when is_binary(public_client_id),
    do: true

  def public?(%__MODULE__{public_client_id: _public_client_id}), do: false

  defmodule Crypto do
    @moduledoc false

    alias Boruta.Oauth.Client
    alias Boruta.SignaturesAdapter

    @spec signature_algorithms() :: list(atom())
    def signature_algorithms, do: SignaturesAdapter.signature_algorithms()

    @spec hash_alg(Client.t()) :: hash_alg :: atom()
    def hash_alg(client), do: SignaturesAdapter.hash_alg(client)

    @spec hash_binary_size(Client.t()) :: binary_size :: integer()
    def hash_binary_size(client), do: SignaturesAdapter.hash_binary_size(client)

    @spec hash(string :: String.t(), client :: Client.t()) :: hash :: String.t()
    def hash(string, client), do: SignaturesAdapter.hash(string, client)

    @spec id_token_sign(payload :: map(), client :: Client.t()) ::
            jwt :: String.t() | {:error, reason :: String.t()}
    def id_token_sign(payload, client), do: SignaturesAdapter.id_token_sign(payload, client)

    @spec verify_id_token_signature(id_token :: String.t(), jwk :: JOSE.JWK.t()) ::
            :ok | {:error, reason :: String.t()}
    def verify_id_token_signature(id_token, jwk), do: SignaturesAdapter.verify_id_token_signature(id_token, jwk)

    @spec userinfo_sign(payload :: map(), client :: Client.t()) ::
            jwt :: String.t() | {:error, reason :: String.t()}
    def userinfo_sign(payload, client), do: SignaturesAdapter.userinfo_sign(payload, client)

    @spec kid_from_private_key(private_pem :: String.t()) :: kid :: String.t()
    def kid_from_private_key(private_pem), do: SignaturesAdapter.kid_from_private_key(private_pem)

    @spec userinfo_signature_type(Client.t()) :: userinfo_token_signature_type :: atom()
    def userinfo_signature_type(client), do: SignaturesAdapter.userinfo_signature_type(client)
  end
end
