defmodule Boruta.Migrations.FixOauthClientsDid do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20250315083414_change_oauth_clients_did_to_text.exs
        alter table(:oauth_clients) do
          modify :did, :text, from: :string
        end
      end
    end
  end
end
