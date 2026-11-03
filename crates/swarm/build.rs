fn main() {
    // Admin manifest — only on the GUI binary (services must not UAC).
    embed_resource::compile("swarm_gui.rc", &["swarm_gui"]);
}
