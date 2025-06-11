defmodule Boruta.Migrations.CodesResponseType do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20250611193221_add_response_type_to_oauth_tokens.exs
        alter table(:oauth_tokens) do
          add :response_type, :string
        end
      end
    end
  end
end

