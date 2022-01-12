defmodule Boruta.Migrations.StorePreviousToken do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20220109161041_add_previous_token_to_oauth_tokens.exs
        alter table(:oauth_tokens) do
          add :previous_token, :string
        end
      end
    end
  end
end
