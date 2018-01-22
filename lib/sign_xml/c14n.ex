defmodule SignXML.C14N do
  defp plain_fake_root_doc(base_doc, node) do
    node = Libxml.Node.extract(node)

    try do
      if node.prev == nil && node.next == nil do
        root = Libxml.doc_get_root_element(base_doc)

        if root == node do
          throw(base_doc)
        end
      end
    catch
      doc -> doc
    end

    # FIXME(melpon): Memory leaks when an exception occurs with this function

    doc = Libxml.copy_doc(base_doc, false)
    new_root = Libxml.doc_copy_node(node, doc, :partial)

    nil = Libxml.doc_set_root_element(doc, new_root)
    copy_parent_namespaces(node, new_root)

    new_root = Libxml.Node.extract(new_root)
    new_root = %{new_root | children: node.children, last: node.last, next: nil, prev: nil}
    :ok = Libxml.Node.apply(new_root)

    doc = Libxml.Node.extract(doc)
    doc = %{doc | private: node.pointer, children: new_root}
    :ok = Libxml.Node.apply(doc)

    new_root = Libxml.Node.extract(new_root)
    set_parent(new_root.children, new_root)

    doc
  end

  defp destroy_fake_doc(base_doc, doc) do
    if doc.pointer == base_doc.pointer do
      :ok
    else
      root = Libxml.doc_get_root_element(doc)
      root = Libxml.Node.extract(root)

      # restore parent pointers of children
      parent = %Libxml.Node{pointer: doc.private}
      set_parent(root.children, parent)

      # prevent recursive removal of children
      root = %{root | children: nil, last: nil}
      Libxml.Node.apply(root)
      Libxml.free_doc(doc)
    end
  end

  defp set_parent(nil, _) do
    :ok
  end

  defp set_parent(%Libxml.Node{} = child, new_root) do
    child = Libxml.Node.extract(child)
    child = %{child | parent: new_root}
    Libxml.Node.apply(child)
    set_parent(child.next, new_root)
  end

  defp cpn_2(nil, _to_node) do
    :ok
  end

  defp cpn_2(new_ns, to_node) do
    new_ns = Libxml.Ns.extract(new_ns)
    href = new_ns.href && Libxml.Char.extract(new_ns.href)
    prefix = new_ns.prefix && Libxml.Char.extract(new_ns.prefix)
    # libxml2 will check if the prefix is already defined
    try do
      Libxml.new_ns(to_node, href.content, prefix.content)
    rescue
      _ -> :ok
    end

    cpn_2(new_ns.next, to_node)
  end

  defp cpn_1(parent, to_node) do
    parent = parent && Libxml.Node.extract(parent)

    if parent != nil &&
         parent.type in [
           :element_node,
           :comment_node,
           :entity_ref_node,
           :pi_node,
           :xinclude_start,
           :xinclude_end
         ] do
      new_ns = parent.more.ns_def
      cpn_2(new_ns, to_node)
      cpn_1(parent.parent, to_node)
    else
      :ok
    end
  end

  defp copy_parent_namespaces(from_node, to_node) do
    from_node = Libxml.Node.extract(from_node)
    cpn_1(from_node.parent, to_node)
  end

  def c14n(node, mode, inclusive_ns_prefixes, with_comments) do
    node = Libxml.Node.extract(node)

    doc =
      if node.type == :document_node do
        node
      else
        plain_fake_root_doc(node.doc, node)
      end

    try do
      Libxml.C14N.doc_dump_memory(doc, nil, mode, inclusive_ns_prefixes, with_comments)
    after
      destroy_fake_doc(node.doc, doc)
    end
  end
end
