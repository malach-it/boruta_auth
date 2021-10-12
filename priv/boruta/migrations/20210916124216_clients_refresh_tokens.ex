defmodule Boruta.Migrations.ClientsRefreshTokens do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20210904185118_add_public_refresh_token_to_clients.exs
        alter table(:oauth_clients) do
          add :public_refresh_token, :boolean, null: false, default: false
        end

        # 20210914115259_add_refresh_token_ttl_to_clients.exs
        alter table(:oauth_clients) do
          add :refresh_token_ttl, :integer, null: false, default: "2592000"
        end

        alter table(:oauth_clients) do
          modify :refresh_token_ttl, :integer, null: false
        end
      end
    end
  end
end
