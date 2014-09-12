#![allow(unused_imports)]
#![allow(dead_code)]

pub mod event {
  use capnp::any_pointer;
  use capnp::capability::{FromClientHook, FromTypelessPipeline};
  use capnp::{text, data};
  use capnp::layout;
  use capnp::layout::{FromStructBuilder, FromStructReader, ToStructReader};
  use capnp::{primitive_list, enum_list, struct_list, text_list, data_list, list_list};
  use capnp::list::ToU16;

  pub static STRUCT_SIZE : layout::StructSize =
    layout::StructSize { data : 2, pointers : 2, preferred_list_encoding : layout::InlineComposite};


  pub struct Reader<'a> { reader : layout::StructReader<'a> }

  impl <'a> layout::FromStructReader<'a> for Reader<'a> {
    fn new(reader: layout::StructReader<'a>) -> Reader<'a> {
      Reader { reader : reader }
    }
  }

  impl <'a> layout::ToStructReader<'a> for Reader<'a> {
    fn struct_reader(&self) -> layout::StructReader<'a> { self.reader }
  }

  impl <'a> Reader<'a> {
    #[inline]
    pub fn get_ts(&self) -> u64 {
      self.reader.get_data_field::<u64>(0)
    }
    #[inline]
    pub fn get_ip_src(&self) -> text::Reader<'a> {
      self.reader.get_pointer_field(0).get_text(::std::ptr::null(), 0)
    }
    pub fn has_ip_src(&self) -> bool {
      !self.reader.get_pointer_field(0).is_null()
    }
    #[inline]
    pub fn get_dport(&self) -> u16 {
      self.reader.get_data_field::<u16>(4)
    }
    #[inline]
    pub fn get_payload(&self) -> data::Reader<'a> {
      self.reader.get_pointer_field(1).get_data(::std::ptr::null(), 0)
    }
    pub fn has_payload(&self) -> bool {
      !self.reader.get_pointer_field(1).is_null()
    }
  }

  pub struct Builder<'a> { builder : layout::StructBuilder<'a> }
  impl <'a> layout::HasStructSize for Builder<'a> {
    #[inline]
    fn struct_size(_unused_self : Option<Builder>) -> layout::StructSize { STRUCT_SIZE }
  }
  impl <'a> layout::FromStructBuilder<'a> for Builder<'a> {
    fn new(builder : layout::StructBuilder<'a>) -> Builder<'a> {
      Builder { builder : builder }
    }
  }
  impl <'a> Builder<'a> {
    pub fn as_reader(&self) -> Reader<'a> {
      FromStructReader::new(self.builder.as_reader())
    }
    #[inline]
    pub fn get_ts(&self) -> u64 {
      self.builder.get_data_field::<u64>(0)
    }
    #[inline]
    pub fn set_ts(&self, value : u64) {
      self.builder.set_data_field::<u64>(0, value);
    }
    #[inline]
    pub fn get_ip_src(&self) -> text::Builder<'a> {
      self.builder.get_pointer_field(0).get_text(::std::ptr::null(), 0)
    }
    #[inline]
    pub fn set_ip_src(&self, value : text::Reader) {
      self.builder.get_pointer_field(0).set_text(value);
    }
    #[inline]
    pub fn init_ip_src(&self, size : uint) -> text::Builder<'a> {
      self.builder.get_pointer_field(0).init_text(size)
    }
    pub fn has_ip_src(&self) -> bool {
      !self.builder.get_pointer_field(0).is_null()
    }
    #[inline]
    pub fn get_dport(&self) -> u16 {
      self.builder.get_data_field::<u16>(4)
    }
    #[inline]
    pub fn set_dport(&self, value : u16) {
      self.builder.set_data_field::<u16>(4, value);
    }
    #[inline]
    pub fn get_payload(&self) -> data::Builder<'a> {
      self.builder.get_pointer_field(1).get_data(::std::ptr::null(), 0)
    }
    #[inline]
    pub fn set_payload(&self, value : data::Reader) {
      self.builder.get_pointer_field(1).set_data(value);
    }
    #[inline]
    pub fn init_payload(&self, size : uint) -> data::Builder<'a> {
      self.builder.get_pointer_field(1).init_data(size)
    }
    pub fn has_payload(&self) -> bool {
      !self.builder.get_pointer_field(1).is_null()
    }
  }

  pub struct Pipeline { _typeless : any_pointer::Pipeline }
  impl FromTypelessPipeline for Pipeline {
    fn new(typeless : any_pointer::Pipeline) -> Pipeline {
      Pipeline { _typeless : typeless }
    }
  }
  impl Pipeline {
  }
}
