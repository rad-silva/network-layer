from iputils import *
import struct


class IP:
    id_counter = 0

    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            ttl -= 1

            if ttl == 0:
                next_hop = self._next_hop(self.meu_endereco)
                proto = IPPROTO_ICMP
                type_msg = 11
                code = 0

                checksum = calc_checksum(struct.pack('!BBHI', 11, 0, 0, 0) + datagrama[:28])
                time_exceded_msg = struct.pack('!BBHI', type_msg, code, checksum, 0) + datagrama[:28]   
                
                header = struct.pack('!BBHHHBBH', 0x45, 0x00, 20+len(time_exceded_msg), identification, \
                            flags+frag_offset, 0x40, proto, 0) + str2addr(self.meu_endereco) + str2addr(src_addr)
                checksum = calc_checksum(header)

                header = struct.pack('!BBHHHBBH', 69, 0, 20+len(time_exceded_msg), identification, \
                            flags+frag_offset, 64, proto, checksum) + str2addr(self.meu_endereco) + str2addr(src_addr)
                
                datagrama = header + time_exceded_msg
                
            
            else:
                next_hop = self._next_hop(dst_addr)

                vihl = 0x45
                checksum = 0x00
                src_addr = str2addr(src_addr) 
                dst_addr = str2addr(dst_addr)

                # Monta o cabeçalho e calcula o checksum
                header = struct.pack('!BBHHHBBH', vihl, (dscp | ecn), (20 + len(payload)), identification, \
                                ((flags << 13) | frag_offset), ttl, proto, checksum) + src_addr + dst_addr
                
                checksum = calc_checksum(header)

                # Atualiza o checksum e cria o datagrama
                header = struct.pack('!BBHHHBBH', vihl, (dscp | ecn), (20 + len(payload)), identification, \
                                ((flags << 13) | frag_offset), ttl, proto, checksum) + src_addr + dst_addr
                
                datagrama = header + payload
            
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.

        print('dest addr = ', dest_addr)
        best_match = None

        for entrada in self.tabela:
            cidr, next_hop = entrada
            rede_addr, mask = cidr.split('/')

            # Converte o endereço da tabela e o endereço de destino em binário
            val_dest, = struct.unpack('!I', str2addr(dest_addr))
            val_rede, = struct.unpack('!I', str2addr(rede_addr))

            # Aplica a máscara de sub-rede para verificar se o endereço de 
            # destino está na mesma rede do endereço da tabela
            if (val_dest & (0xFFFFFFFF << (32 - int(mask)))) == val_rede:
                # Verifica se é a melhor correspondência até o momento (maior máscara)
                if (best_match is None) or (int(mask) > int(best_match[0].split('/')[1])):
                    best_match = entrada

        if best_match is not None:
            return best_match[1]  # Retorna o next_hop da melhor correspondência encontrada
        
        return None # Retorna indicador de que não há endereço correspondente na tabela

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela
        print(self.tabela)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        vihl = 0x45  # Versão 4, tamanho do cabeçalho (Internet Header Length ) 5 palavras de 32 bits (5 * 4 = 20 bytes)
        dscpecn = 0x00
        total_len = 20 + len(segmento)
        identification = IP.id_counter
        flagsfrag = 0x00
        ttl = 0x40 #time_to_live  64 em decimal
        protocol = 0x06 # Protocolo TCP
        checksum = 0x00 # Placeholder para o checksum
        src_addr = str2addr(self.meu_endereco) 
        dest_addr = str2addr(dest_addr)

        # Monta o cabeçalho e calcula o checksum
        header = struct.pack('!BBHHHBBH', vihl, dscpecn, total_len, identification, \
                             flagsfrag, ttl, protocol, checksum) + src_addr + dest_addr
        
        checksum = calc_checksum(header)

        # Atualiza o checksum e cria o datagrama
        header = struct.pack('!BBHHHBBH', vihl, dscpecn, total_len, identification, \
                     flagsfrag, ttl, protocol, checksum) + src_addr + dest_addr
        
        datagrama = header + segmento

        # Incrementa o identificador
        IP.id_counter += 1

        # Envia o datagrama
        self.enlace.enviar(datagrama, next_hop)
