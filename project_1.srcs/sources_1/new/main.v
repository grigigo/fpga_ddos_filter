`timescale 1ns / 1ps

module main(
    input wire clk,
    input wire rst,
    input wire [7:0] data,

    output reg [7:0] pb,
    output reg [6:0] start,
    output reg [6:0] pend,
    output reg is_end,
    output reg [7:0] count,
    output reg [7:0] print,
    
    output reg [7:0] ip_protocol, 
    output reg [5:0] flag,
    output reg [31:0] ipsrc,
    output reg [31:0] ipdst,
    output reg [15:0] dport,
    output reg [15:0] sport,
    output reg [47:0] macdst,
    output reg [47:0] macsrc,
    output reg [31:0] seq_num,
    output reg [31:0] ack_num,
    output reg result
);

    integer i;
    integer k;
    reg isfor;
    integer fin;
    reg [7:0] addr_reg;
    reg [3:0] hex_count;
    reg [7:0] packet [127:0];
    reg [7:0] error;
    reg [1:0] num;
    reg is_analyze;
    reg [31:0] my_ip;
    reg [1023:0] temp;
    
    reg [31:0] ram_ipsrc [127:0];
    reg [31:0] ram_ipdst [127:0];
    reg [15:0] ram_dport [127:0];
    reg [15:0] ram_sport [127:0];
    reg [7:0] ram_state [127:0];
    reg [31:0] ram_seq [127:0];
    reg [31:0] ram_ack [127:0];
    reg [1023:0] ram_pack [127:0];
    reg [1:0] ram_i [127:0];
    reg [559:0] synack;

    always @(posedge clk or posedge rst)
    begin
        // Инициализация
        if (rst) begin
            for (i = 0; i < 128; i = i + 1) begin
                ram_state[i] = 'b0;
                ram_i[i] = 'b0;
            end
            my_ip = 'hc0a8030c;
            fin = $fopen("filein.txt", "w");
            $fclose(fin);
            addr_reg <= 0;
            hex_count <= 0;
            start <= 0;
            pend <= 0;
            is_end <= 0;
            count <= -2;
            is_analyze = 0;
        end else begin
            // Чтение пакетов
            packet[addr_reg] = data;
            pb = packet[addr_reg];

            // Определение начала/конца пакета
            if (packet[addr_reg] == 8'h55)
                hex_count = hex_count + 1;
            else if (packet[addr_reg] == 8'hd5 && hex_count == 7)
                if (start) begin
                    pend = addr_reg - 8;
                    is_end = ~is_end;
                    hex_count = 0;
                end else begin
                    start = addr_reg;
                    hex_count = 0;
                end
            else
                hex_count = 0;
            addr_reg = addr_reg + 1;
        end
    end

    // Получение информации о пакете
    always @(is_end) begin
        ip_protocol = packet[start + 22];
        if (ip_protocol == 8'h06) begin
            macdst = {packet[start - 1], packet[start], packet[start + 1], packet[start + 2], packet[start + 3], packet[start + 4]};
            macsrc = {packet[start + 5], packet[start + 6], packet[start + 7], packet[start + 8], packet[start + 9], packet[start + 10]};
            ipsrc = {packet[start + 25], packet[start + 26], packet[start + 27], packet[start + 28]};
            ipdst = {packet[start + 29], packet[start + 30], packet[start + 31], packet[start + 32]};
            sport = {packet[start + 33], packet[start + 34]};
            dport = {packet[start + 35], packet[start + 36]};
            seq_num = {packet[start + 37], packet[start + 38], packet[start + 39], packet[start + 40]};
            ack_num = {packet[start + 41], packet[start + 42], packet[start + 43], packet[start + 44]};
            flag = packet[start + 46][5:0];
            is_analyze = ~is_analyze;
        end else 
            print <= 10;
        start = 1;
        addr_reg = 0;
        count = count + 1;
    end
// ---------------------------------------------------------------------------------------------------
    always @(is_analyze) begin // 1
        fin = $fopen("filein.txt", "a");
        result = 0;
        for (i = 128; i > 0; i = i - 1) begin
            if (i > 127 - pend)
                temp[i*8-1 -: 8] = packet[128 - i];
            else
                temp[i*8-1 -: 8] = 8'bxxxx_xxxx;
        end
        
        begin : forloop
            i = -1;
            for (k = 0; k < 128; k = k + 1)
                if (dport == ram_sport[k] || dport == ram_dport[k])
                    if (sport == ram_sport[k] || sport == ram_dport[k])
                        if (ipdst == ram_ipsrc[k] || ipdst == ram_ipdst[k])
                            if (ipsrc == ram_ipsrc[k] || ipsrc == ram_ipdst[k]) begin
                                i = k;
                                disable forloop;
                            end
        end
        $fwrite(fin, "i: %b\n", i);
        
        // SYN
        if (flag == 6'b000010) begin // 2
            if (i == -1) begin
                begin : forloop1
                for (i = 0; i < 128; i = i + 1)
                    if (ram_state[i] == 8'b0000_0000) begin
                        if (ipsrc == my_ip)
                            ram_state[i] = 8'b0000_0001;
                        else
                            ram_state[i] = 8'b0000_0010;
                        ram_sport[i] = sport;
                        ram_dport[i] = dport;
                        ram_ipsrc[i] = ipsrc;
                        ram_ipdst[i] = ipdst;
                        result = 1;
                        disable forloop1;
                    end
                end
            end
            $fwrite(fin, "Пришел SYN. Соединение инициировано!\n");
            $fwrite(fin, "State: %b\n", ram_state[i]);
            $fwrite(fin, "Result: %b\n\n", result);
            
        // RST
        end else if (flag[2]) begin // 2
            $fwrite(fin, "Пришел RST. ");
            if (i != -1) begin
                ram_sport[i] = 'b0;
                ram_dport[i] = 'b0;
                ram_ipsrc[i] = 'b0;
                ram_ipdst[i] = 'b0;
                ram_state[i] = 'b0;
                result = 1;
                $fwrite(fin, "Соединение разорвано!\n");
            end
            $fwrite(fin, "State: %b\n", ram_state[i]);
            $fwrite(fin, "Result: %b\n\n", result);
            
        // FIN
        end else if (flag[0]) begin // 2
            result = 0;
            $fwrite(fin, "Пришел FIN. ");
            if (i != -1) // 3
                if (ipsrc == my_ip) begin
                    if (ram_state[i] == 8'b0000_0100) begin
                        ram_state[i] = 8'b0001_0000;
                        result = 1;
                        $fwrite(fin, "Ты инициируешь закрытие соединения!\n");
                    end else if (ram_state[i] == 8'b0100_0000) begin
                        ram_state[i] = 8'b1000_0000;
                        result = 1;
                        $fwrite(fin, "Ты отвечаешь на закрытие соединения!\n");
                    end
                end else if (ipdst == my_ip) begin
                    if (ram_state[i] == 8'b0000_0100) begin
                        ram_state[i] = 8'b0100_0000;
                        result = 1;
                        $fwrite(fin, "Тебе пришло закрытие соединения!\n");
                    end else if (ram_state[i] == 8'b0010_0000) begin
                        ram_state[i] = 'b0;
                        result = 1;
                        $fwrite(fin, "Тебе пришло подтверждение на закрытие соединения!\n");
                    end
                end
            $fwrite(fin, "State: %b\n", ram_state[i]);
            $fwrite(fin, "Result: %b\n\n", result);
            
        // SYN-ACK
        end else if (flag[1] && flag[4]) begin // 2
            result = 0;
            $fwrite(fin, "Пришел SYN-ACK. ");
            if (i != -1) begin // 3
                if (ipdst == my_ip) begin // 4
                    if (ram_state[i] == 8'b0000_0001) begin
                        result = 1;
                        ram_state[i] = 8'b0000_0100;
                        $fwrite(fin, "Соединение установлено!\n");
                    end
                end else if (ipsrc == my_ip) begin // 4
                    if (ram_state[i] == 8'b0000_0010) begin
                        result = 1;
                        $fwrite(fin, "Пакет пропущен!\n");
                    end
                end // 4
            end // 3
            $fwrite(fin, "State: %b\n", ram_state[i]);
            $fwrite(fin, "Result: %b\n\n", result);
            
        // PSH
        end else if (flag[3]) begin // 2
            $fwrite(fin, "Пришел PSH. ");
            result = 0;
            if (i != -1) begin
                if (ram_state[i] == 'b0000_0100) begin
                    result = 1;
                    $fwrite(fin, "Пропущен PSH пакет!\n");
                end
            end
            $fwrite(fin, "State: %b\n", ram_state[i]);
            $fwrite(fin, "Result: %b\n\n", result);
            
        // ACK
        end else if (flag[4]) begin // 2
            $fwrite(fin, "Пришел ACK. ");
            result = 0;
            if (i != -1) begin // 3
                if (ram_state[i] == 'b0000_0100) begin // 4
                    result = 1;
                    $fwrite(fin, "Пропущен ACK пакет!\n");
                end else if (ipdst == my_ip) begin // 4
                    if (ram_state[i] == 'b0001_0000) begin // 5
                        ram_state[i] = 'b0010_0000;
                        result = 1;
                        $fwrite(fin, "Тебе пришел ответ на закрытие соединения!\n");
                    end else if (ram_state[i] == 'b1000_0000) begin // 5
                        result = 1;
                        ram_state[i] = 'b0000_0000;
                        $fwrite(fin, "Соединение закрыто!\n");
                    end else if (ram_state[i] == 8'b0000_0010) begin // 5
                        result = 1;
                        ram_state[i] = 'b0000_0100;
                    end // 5
                end else if (ipsrc == my_ip) begin // 4
                    if (ram_state[i] == 'b0010_0000) begin
                        result = 1;
                        $fwrite(fin, "Соединение закрыто!\n");
                        ram_state[i] = 'b0000_0000;
                    end else // 5
                        result = 1;
                end // 4
            end // 3
            $fwrite(fin, "State: %b\n", ram_state[i]);
            $fwrite(fin, "Result: %b\n\n", result);
        end // 2
        $fclose(fin);
    end // 1

endmodule