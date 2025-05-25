defmodule Boruta.Migrations.PublicClientId do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20250524142111_add_public_client_id_to_oauth_tokens.exs
        alter table(:oauth_tokens) do
          add :public_client_id, :text
        end

        alter table(:oauth_clients) do
          add :check_public_client_id, :boolean, default: false, null: false
        end
      end
    end
  end
end
