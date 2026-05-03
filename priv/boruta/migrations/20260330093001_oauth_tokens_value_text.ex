defmodule Boruta.Migrations.OauthTokensValueText do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20260330093000_change_oauth_tokens_value_to_text.exs
        alter table(:oauth_tokens) do
          modify :value, :text, from: :string
        end
      end
    end
  end
end
