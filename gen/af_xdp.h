
struct ax_socket;
struct ax_desc
{
	int			fd;
	struct ax_socket	*axs;
};

struct ax_rx_handle
{
	uint32_t	rring_idx;	/* Index in the Rx ring */
	uint32_t	fring_idx;	/* Index in the Fill ring */
	unsigned int	npkts;
};

static inline void
ax_rx_handle_advance(struct ax_rx_handle *handle)
{
	handle->rring_idx++;
	handle->fring_idx++;
}

static inline int
ax_get_fd(struct ax_desc *ax_desc)
{
	return ax_desc->fd;
}

struct ax_desc *
	ax_open(const char *);
void	ax_close(struct ax_desc *);
unsigned int
	ax_wait_for_packets(struct ax_desc *, struct ax_rx_handle *);
char *
	ax_get_rx_buf(struct ax_desc *, uint32_t *, struct ax_rx_handle *);
char *
	ax_get_tx_buf(struct ax_desc *, uint32_t **, uint32_t, int);
void	ax_complete_tx(struct ax_desc *, unsigned int);
uint32_t
	ax_prepare_tx(struct ax_desc *, unsigned int *);
void	ax_complete_rx(struct ax_desc *, unsigned int);
