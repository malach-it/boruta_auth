defmodule Boruta.Migrations.AuthorizationCodeChains do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20221009100713_add_previous_code_to_oauth_tokens.exs
        alter table(:oauth_tokens) do
          add :previous_code, :string
        end
      end
    end
  end
end
