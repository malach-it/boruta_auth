defmodule Boruta.Migrations.ClientAuthenticationMethods do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20221118154717_add_jwt_public_key_to_oauth_clients.exs
        alter table(:oauth_clients) do
          add :jwt_public_key, :text
        end

        # 20221118155336_add_token_endpoint_auth_method_to_oauth_clients.exs
        alter table(:oauth_clients) do
          add :token_endpoint_auth_methods, {:array, :string}, null: false,
            default: ["client_secret_basic", "client_secret_post"]
        end

        # 20221121100117_add_token_endpoint_jwt_auth_alg.exs
        alter table(:oauth_clients) do
          add :token_endpoint_jwt_auth_alg, :string, default: "HS256", null: false
        end
      end
    end
  end
end

