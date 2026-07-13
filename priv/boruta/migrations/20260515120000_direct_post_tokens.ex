defmodule Boruta.Migrations.DirectPostTokens do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20260515120000_add_direct_post_tokens_to_oauth_tokens.exs
        alter table(:oauth_tokens) do
          add(:id_token, :text)
        end
      end
    end
  end
end
