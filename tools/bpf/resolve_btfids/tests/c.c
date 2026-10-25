struct late_unique { int a, b, c; };
struct late_unique third;
asm(".pushsection .BTF_ids,\"aw\"\n"
    ".balign 4\n"
    "__BTF_ID__set__fixture:\n .zero 4\n"
    "__BTF_ID__struct__duplicate_type__1:\n .zero 4\n"
    "__BTF_ID__struct__late_unique__2:\n .zero 4\n"
    ".size __BTF_ID__set__fixture, .-__BTF_ID__set__fixture\n"
    ".popsection\n");
