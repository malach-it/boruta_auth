defmodule Boruta.Migrations.ClientIdTokenKid do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20230515150324_add_id_token_kid_to_clients.exs
        alter table(:oauth_clients) do
          add :id_token_kid, :string
        end
      end
    end
  end
end
