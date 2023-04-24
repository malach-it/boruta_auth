defmodule Boruta.Migrations.OptionalPublicKeyForOauthClients do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def up do
        # 20221108102337_optional_public_key_for_oauth_clients.exs
        alter table(:oauth_clients) do
          modify :public_key, :text, null: true
        end
      end
      def down do
         # 20221108102337_optional_public_key_for_oauth_clients.exs
         alter table(:oauth_clients) do
           modify :public_key, :text, null: false
         end
      end
    end
  end
end

