`timescale 1ns / 1ps

module testmain();
    reg rst;
    reg clk;
    
    reg [7:0] data;
    reg [7:0] mem1;
    reg [7:0] mem2;
    
    wire [7:0] pb;

    wire [6:0] start;
    wire [6:0] pend;
    wire is_end;
    wire [7:0] count;

    wire [5:0] flag;
    wire [31:0] ipsrc;
    wire [31:0] ipdst;
    wire [15:0] dport;
    wire [15:0] sport;
    wire [47:0] macdst;
    wire [47:0] macsrc;
    wire [31:0] seq_num;
    wire [31:0] ack_num;
    wire [7:0] ip_protocol;
    wire result;

    integer fout;
    reg [7:0] error;
    wire [7:0] print;

    initial
    begin
        clk = 0;
        fout = $fopen("fileout.txt", "r");

        rst = 1;
        #10 rst = 0;
    end

    always #10 clk = ~clk;

    always @(posedge clk)
    begin
        // Чтение из файла 2 байта (два символа ASCII)
        error = $fread(mem1, fout); // Читает ASCII
        error = $fread(mem2, fout); // Читает ASCII

        // Перевод каждого байта в 4 битовый hex
        if (mem1 < 8'h3a)
            data[7:4] = mem1 - 8'h30;
        else
            data[7:4] = mem1 - 8'h57;

        if (mem2 < 8'h3a)
            data[3:0] = mem2 - 8'h30;
        else
            data[3:0] = mem2 - 8'h57;
    end
    

    main test(
        .clk(clk),
        .data(data),
        .rst(rst),
        .pb(pb),
        .flag(flag),
        .start(start),
        .pend(pend),

        .count(count),
        .ip_protocol(ip_protocol),
        .ipsrc(ipsrc),
        .ipdst(ipdst),
        .dport(dport),
        .sport(sport),
        .macdst(macdst),
        .macsrc(macsrc),
        .seq_num(seq_num),
        .ack_num(ack_num),
        .is_end(is_end),
        .result(result),
        .print(print)
        
    );

endmodule
