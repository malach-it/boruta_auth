defmodule Boruta.Ecto.Errors do
  @moduledoc false

  @spec message_from_changeset(changeset :: Ecto.Changeset.t()) :: error_message :: String.t()
  def message_from_changeset(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} ->
      msg
    end)
    |> Enum.flat_map(fn {key, messages} ->
      Enum.map(messages, fn message -> "#{key} #{message}" end)
    end)
    |> Enum.join(", ")
  end
end
