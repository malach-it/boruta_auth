defmodule Boruta.Migrations.ClientsResponseMode do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20240914073117_add_response_mode_to_oauth_clients.exs
        alter table(:oauth_clients) do
          add :response_mode, :string, default: "direct_post"
        end
      end
    end
  end
end
