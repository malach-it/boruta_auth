defmodule Boruta.Repo.Migrations.InsertPublicClient do
  use Ecto.Migration

  import Boruta.Config,
    only: [token_generator: 0, issuer: 0]

  def up do
    private_key = JOSE.JWK.generate_key({:ec, "P-256"})
    public_key = JOSE.JWK.to_public(private_key)

    {_type, public_pem} = JOSE.JWK.to_pem(public_key)
    {_type, private_pem} = JOSE.JWK.to_pem(private_key)

    alter table(:oauth_clients) do
      add(:public_client_id, :string)
    end

    execute("""
    INSERT INTO oauth_clients (
      id,
      public_client_id,
      name,
      secret,
      confidential,
      access_token_ttl,
      authorization_code_ttl,
      refresh_token_ttl,
      id_token_ttl,
      redirect_uris,
      authorize_scope,
      supported_grant_types,
      id_token_signature_alg,
      public_key,
      private_key,
      inserted_at,
      updated_at
    ) VALUES (
      gen_random_uuid(),
      '#{issuer()}',
      'public client',
      '#{token_generator().secret(struct(Boruta.Ecto.Client))}',
      true,
      86400,
      60,
      86400,
      86400,
      '{}',
      false,
      '{"client_credentials", "password", "authorization_code", "preauthorized_code", "refresh_token", "implicit", "revoke", "introspect"}',
      'ES256',
      '#{public_pem}',
      '#{private_pem}',
      current_timestamp,
      current_timestamp
    )
    """)
  end

  def down do
    alter table(:oauth_clients) do
      remove(:public_client_id, :string)
    end
  end
end
