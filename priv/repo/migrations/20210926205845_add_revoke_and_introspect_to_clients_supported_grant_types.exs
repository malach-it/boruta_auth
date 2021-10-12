defmodule Boruta.Repo.Migrations.AddRevokeAndIntrospectToClientsSupportedGrantTypes do
  use Ecto.Migration

  def up do
     execute("""
      ALTER TABLE oauth_clients
        ALTER COLUMN supported_grant_types TYPE varchar(255)[]
          USING (supported_grant_types || ARRAY['revoke'::varchar(255), 'introspect'::varchar(255)])
      """)

     execute("""
      ALTER TABLE oauth_clients
        ALTER COLUMN supported_grant_types
          SET DEFAULT ARRAY['client_credentials', 'password', 'authorization_code', 'refresh_token', 'implicit', 'revoke', 'introspect']
     """)
  end
end
