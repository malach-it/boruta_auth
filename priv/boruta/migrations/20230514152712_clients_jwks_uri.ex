defmodule Boruta.Migrations.ClientsJwksUri do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20230514122748_add_jwks_uri_to_clients.exs
        alter table(:oauth_clients) do
          add :jwks_uri, :string
        end
      end
    end
  end
end

