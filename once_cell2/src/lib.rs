#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]

pub mod race {
	pub struct LazyBox<T, F = fn() -> T> {
		cell: once_cell::race::OnceBox<T>,
		init: F,
	}

	impl<T, F> LazyBox<T, F> {
		pub const fn new(init: F) -> Self {
			LazyBox {
				cell: once_cell::race::OnceBox::<T>::new(),
				init,
			}
		}
	}

	impl<T, F> std::ops::Deref for LazyBox<T, F> where F: Fn() -> T {
		type Target = T;

		fn deref(&self) -> &Self::Target {
			self.cell.get_or_init(|| Box::new((self.init)()))
		}
	}
}
