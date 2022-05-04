defmodule Boruta.Migrations.ClientsPublicRevoke do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def up do
        # 20210926200753_add_public_revoke_to_clients.exs
        alter table(:oauth_clients) do
          add(:public_revoke, :boolean, null: false, default: false)
        end

        # 20210926205845_add_revoke_and_introspect_to_clients_supported_grant_types.exs
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

      def down do
        # 20210926205845_add_revoke_and_introspect_to_clients_supported_grant_types.exs

        execute("""
        ALTER TABLE oauth_clients
          ALTER COLUMN supported_grant_types TYPE varchar(255)[]
            USING ARRAY(
              SELECT supported_grant_type
              FROM supported_grant_types
              WHERE supported_grant_type NOT IN ('revoke', 'introspect')
            )
        """)

        execute("""
         ALTER TABLE oauth_clients
           ALTER COLUMN supported_grant_types
             SET DEFAULT ARRAY['client_credentials', 'password', 'authorization_code', 'refresh_token', 'implicit']
        """)

        # 20210926200753_add_public_revoke_to_clients.exs
        alter table(:oauth_clients) do
          remove(:public_revoke)
        end
      end
    end
  end
end
