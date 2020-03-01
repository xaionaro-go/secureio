package secureio

type packetIDStorage struct {
	latestPacketIDValue uint64

	// it's just a lookup table where each bit corresponds to a specific PacketID value
	// We could've utilize something just like uint256 instead of []uint64 if Go would've
	// support it.
	table []uint64
}

func newPacketIDStorage(depth uint) *packetIDStorage {
	stor := &packetIDStorage{}
	if depth > 0 {
		stor.table = make([]uint64, (depth+63)/64)
	}
	return stor
}

func (stor *packetIDStorage) Push(packetID uint64) (result bool) {
	switch {
	case packetID > stor.latestPacketIDValue:
		if stor.table != nil {
			stor.shiftValue(uint(packetID - stor.latestPacketIDValue))
			stor.setAtOffset(0, true)
		}
		stor.latestPacketIDValue = packetID
		result = true
		return
	case packetID == stor.latestPacketIDValue:
		result = false
		return
	case stor.latestPacketIDValue-packetID >= uint64(len(stor.table)<<6 /* *64 */):
		result = false
		return
	default:
		offset := uint(stor.latestPacketIDValue - packetID)
		if stor.getAtOffset(offset) {
			result = false
			return
		}
		stor.setAtOffset(offset, true)
		result = true
		return
	}
}

func (stor *packetIDStorage) shiftValue(bitsAmount uint) {
	l := len(stor.table)
	var r uint64
	for idx := 0; idx < l; idx++ {
		v := stor.table[idx]
		stor.table[idx] = r | (v << bitsAmount)
		r = v >> (64 - bitsAmount)
	}
}

func (stor *packetIDStorage) setAtOffset(offset uint, value bool) {
	bit := uint64(1) << (offset & 0x3f)
	idx := offset >> 6 /* /64 */
	if value {
		stor.table[idx] |= bit
	} else {
		stor.table[idx] &= ^bit
	}
}

func (stor *packetIDStorage) getAtOffset(offset uint) (value bool) {
	bit := uint64(1) << (offset & 0x3f)
	idx := offset >> 6 /* /64 */
	return stor.table[idx]&bit != 0
}
