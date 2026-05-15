tmux_socket := "/workspaces/dotnet-samples/.devcontainer/.tmux"
session := "work"

# Start or attach to a tmux session
tmux session:
    tmux -S {{tmux_socket}} new -d -s {{session}}
    tmux -S {{tmux_socket}} attach -t {{session}}

tmuxd session:
    devcontainer exec --workspace-folder . tmux -S .devcontainer/.tmux attach -t {{session}}