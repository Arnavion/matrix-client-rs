pub(crate) fn try_split_prefix<const N: usize>(s: &[u8]) -> Option<(&[u8; N], &[u8])> {
	if s.len() >= N {
		let (a, b) = s.split_at(N);
		Some((a.try_into().expect("guaranteed by split_at"), b))
	}
	else {
		None
	}
}

pub(crate) fn try_split_suffix<const N: usize>(s: &[u8]) -> Option<(&[u8], &[u8; N])> {
	if s.len() >= N {
		let (a, b) = s.split_at(s.len() - N);
		Some((a, b.try_into().expect("guaranteed by split_at")))
	}
	else {
		None
	}
}
