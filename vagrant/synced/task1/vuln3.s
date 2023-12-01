
vuln3-32:     file format elf32-i386


Disassembly of section .init:

000004e0 <_init>:
 4e0:	53                   	push   %ebx
 4e1:	83 ec 08             	sub    $0x8,%esp
 4e4:	e8 37 01 00 00       	call   620 <__x86.get_pc_thunk.bx>
 4e9:	81 c3 c7 1a 00 00    	add    $0x1ac7,%ebx
 4ef:	8b 83 44 00 00 00    	mov    0x44(%ebx),%eax
 4f5:	85 c0                	test   %eax,%eax
 4f7:	74 05                	je     4fe <_init+0x1e>
 4f9:	e8 da 00 00 00       	call   5d8 <__gmon_start__@plt>
 4fe:	83 c4 08             	add    $0x8,%esp
 501:	5b                   	pop    %ebx
 502:	c3                   	ret    

Disassembly of section .plt:

00000510 <.plt>:
 510:	ff b3 04 00 00 00    	pushl  0x4(%ebx)
 516:	ff a3 08 00 00 00    	jmp    *0x8(%ebx)
 51c:	00 00                	add    %al,(%eax)
	...

00000520 <printf@plt>:
 520:	ff a3 0c 00 00 00    	jmp    *0xc(%ebx)
 526:	68 00 00 00 00       	push   $0x0
 52b:	e9 e0 ff ff ff       	jmp    510 <.plt>

00000530 <fclose@plt>:
 530:	ff a3 10 00 00 00    	jmp    *0x10(%ebx)
 536:	68 08 00 00 00       	push   $0x8
 53b:	e9 d0 ff ff ff       	jmp    510 <.plt>

00000540 <fread@plt>:
 540:	ff a3 14 00 00 00    	jmp    *0x14(%ebx)
 546:	68 10 00 00 00       	push   $0x10
 54b:	e9 c0 ff ff ff       	jmp    510 <.plt>

00000550 <strcpy@plt>:
 550:	ff a3 18 00 00 00    	jmp    *0x18(%ebx)
 556:	68 18 00 00 00       	push   $0x18
 55b:	e9 b0 ff ff ff       	jmp    510 <.plt>

00000560 <puts@plt>:
 560:	ff a3 1c 00 00 00    	jmp    *0x1c(%ebx)
 566:	68 20 00 00 00       	push   $0x20
 56b:	e9 a0 ff ff ff       	jmp    510 <.plt>

00000570 <strerror@plt>:
 570:	ff a3 20 00 00 00    	jmp    *0x20(%ebx)
 576:	68 28 00 00 00       	push   $0x28
 57b:	e9 90 ff ff ff       	jmp    510 <.plt>

00000580 <exit@plt>:
 580:	ff a3 24 00 00 00    	jmp    *0x24(%ebx)
 586:	68 30 00 00 00       	push   $0x30
 58b:	e9 80 ff ff ff       	jmp    510 <.plt>

00000590 <__libc_start_main@plt>:
 590:	ff a3 28 00 00 00    	jmp    *0x28(%ebx)
 596:	68 38 00 00 00       	push   $0x38
 59b:	e9 70 ff ff ff       	jmp    510 <.plt>

000005a0 <fprintf@plt>:
 5a0:	ff a3 2c 00 00 00    	jmp    *0x2c(%ebx)
 5a6:	68 40 00 00 00       	push   $0x40
 5ab:	e9 60 ff ff ff       	jmp    510 <.plt>

000005b0 <fopen@plt>:
 5b0:	ff a3 30 00 00 00    	jmp    *0x30(%ebx)
 5b6:	68 48 00 00 00       	push   $0x48
 5bb:	e9 50 ff ff ff       	jmp    510 <.plt>

000005c0 <__errno_location@plt>:
 5c0:	ff a3 34 00 00 00    	jmp    *0x34(%ebx)
 5c6:	68 50 00 00 00       	push   $0x50
 5cb:	e9 40 ff ff ff       	jmp    510 <.plt>

Disassembly of section .plt.got:

000005d0 <__cxa_finalize@plt>:
 5d0:	ff a3 40 00 00 00    	jmp    *0x40(%ebx)
 5d6:	66 90                	xchg   %ax,%ax

000005d8 <__gmon_start__@plt>:
 5d8:	ff a3 44 00 00 00    	jmp    *0x44(%ebx)
 5de:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

000005e0 <_start>:
 5e0:	31 ed                	xor    %ebp,%ebp
 5e2:	5e                   	pop    %esi
 5e3:	89 e1                	mov    %esp,%ecx
 5e5:	83 e4 f0             	and    $0xfffffff0,%esp
 5e8:	50                   	push   %eax
 5e9:	54                   	push   %esp
 5ea:	52                   	push   %edx
 5eb:	e8 22 00 00 00       	call   612 <_start+0x32>
 5f0:	81 c3 c0 19 00 00    	add    $0x19c0,%ebx
 5f6:	8d 83 20 e9 ff ff    	lea    -0x16e0(%ebx),%eax
 5fc:	50                   	push   %eax
 5fd:	8d 83 c0 e8 ff ff    	lea    -0x1740(%ebx),%eax
 603:	50                   	push   %eax
 604:	51                   	push   %ecx
 605:	56                   	push   %esi
 606:	ff b3 48 00 00 00    	pushl  0x48(%ebx)
 60c:	e8 7f ff ff ff       	call   590 <__libc_start_main@plt>
 611:	f4                   	hlt    
 612:	8b 1c 24             	mov    (%esp),%ebx
 615:	c3                   	ret    
 616:	66 90                	xchg   %ax,%ax
 618:	66 90                	xchg   %ax,%ax
 61a:	66 90                	xchg   %ax,%ax
 61c:	66 90                	xchg   %ax,%ax
 61e:	66 90                	xchg   %ax,%ax

00000620 <__x86.get_pc_thunk.bx>:
 620:	8b 1c 24             	mov    (%esp),%ebx
 623:	c3                   	ret    
 624:	66 90                	xchg   %ax,%ax
 626:	66 90                	xchg   %ax,%ax
 628:	66 90                	xchg   %ax,%ax
 62a:	66 90                	xchg   %ax,%ax
 62c:	66 90                	xchg   %ax,%ax
 62e:	66 90                	xchg   %ax,%ax

00000630 <deregister_tm_clones>:
 630:	e8 e4 00 00 00       	call   719 <__x86.get_pc_thunk.dx>
 635:	81 c2 7b 19 00 00    	add    $0x197b,%edx
 63b:	8d 8a 58 00 00 00    	lea    0x58(%edx),%ecx
 641:	8d 82 58 00 00 00    	lea    0x58(%edx),%eax
 647:	39 c8                	cmp    %ecx,%eax
 649:	74 1d                	je     668 <deregister_tm_clones+0x38>
 64b:	8b 82 38 00 00 00    	mov    0x38(%edx),%eax
 651:	85 c0                	test   %eax,%eax
 653:	74 13                	je     668 <deregister_tm_clones+0x38>
 655:	55                   	push   %ebp
 656:	89 e5                	mov    %esp,%ebp
 658:	83 ec 14             	sub    $0x14,%esp
 65b:	51                   	push   %ecx
 65c:	ff d0                	call   *%eax
 65e:	83 c4 10             	add    $0x10,%esp
 661:	c9                   	leave  
 662:	c3                   	ret    
 663:	90                   	nop
 664:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
 668:	f3 c3                	repz ret 
 66a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

00000670 <register_tm_clones>:
 670:	e8 a4 00 00 00       	call   719 <__x86.get_pc_thunk.dx>
 675:	81 c2 3b 19 00 00    	add    $0x193b,%edx
 67b:	55                   	push   %ebp
 67c:	8d 8a 58 00 00 00    	lea    0x58(%edx),%ecx
 682:	8d 82 58 00 00 00    	lea    0x58(%edx),%eax
 688:	29 c8                	sub    %ecx,%eax
 68a:	89 e5                	mov    %esp,%ebp
 68c:	53                   	push   %ebx
 68d:	c1 f8 02             	sar    $0x2,%eax
 690:	89 c3                	mov    %eax,%ebx
 692:	83 ec 04             	sub    $0x4,%esp
 695:	c1 eb 1f             	shr    $0x1f,%ebx
 698:	01 d8                	add    %ebx,%eax
 69a:	d1 f8                	sar    %eax
 69c:	74 14                	je     6b2 <register_tm_clones+0x42>
 69e:	8b 92 4c 00 00 00    	mov    0x4c(%edx),%edx
 6a4:	85 d2                	test   %edx,%edx
 6a6:	74 0a                	je     6b2 <register_tm_clones+0x42>
 6a8:	83 ec 08             	sub    $0x8,%esp
 6ab:	50                   	push   %eax
 6ac:	51                   	push   %ecx
 6ad:	ff d2                	call   *%edx
 6af:	83 c4 10             	add    $0x10,%esp
 6b2:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 6b5:	c9                   	leave  
 6b6:	c3                   	ret    
 6b7:	89 f6                	mov    %esi,%esi
 6b9:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

000006c0 <__do_global_dtors_aux>:
 6c0:	55                   	push   %ebp
 6c1:	89 e5                	mov    %esp,%ebp
 6c3:	53                   	push   %ebx
 6c4:	e8 57 ff ff ff       	call   620 <__x86.get_pc_thunk.bx>
 6c9:	81 c3 e7 18 00 00    	add    $0x18e7,%ebx
 6cf:	83 ec 04             	sub    $0x4,%esp
 6d2:	80 bb 58 00 00 00 00 	cmpb   $0x0,0x58(%ebx)
 6d9:	75 27                	jne    702 <__do_global_dtors_aux+0x42>
 6db:	8b 83 40 00 00 00    	mov    0x40(%ebx),%eax
 6e1:	85 c0                	test   %eax,%eax
 6e3:	74 11                	je     6f6 <__do_global_dtors_aux+0x36>
 6e5:	83 ec 0c             	sub    $0xc,%esp
 6e8:	ff b3 54 00 00 00    	pushl  0x54(%ebx)
 6ee:	e8 dd fe ff ff       	call   5d0 <__cxa_finalize@plt>
 6f3:	83 c4 10             	add    $0x10,%esp
 6f6:	e8 35 ff ff ff       	call   630 <deregister_tm_clones>
 6fb:	c6 83 58 00 00 00 01 	movb   $0x1,0x58(%ebx)
 702:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 705:	c9                   	leave  
 706:	c3                   	ret    
 707:	89 f6                	mov    %esi,%esi
 709:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

00000710 <frame_dummy>:
 710:	55                   	push   %ebp
 711:	89 e5                	mov    %esp,%ebp
 713:	5d                   	pop    %ebp
 714:	e9 57 ff ff ff       	jmp    670 <register_tm_clones>

00000719 <__x86.get_pc_thunk.dx>:
 719:	8b 14 24             	mov    (%esp),%edx
 71c:	c3                   	ret    

0000071d <copyData>:
 71d:	55                   	push   %ebp
 71e:	89 e5                	mov    %esp,%ebp
 720:	53                   	push   %ebx
 721:	81 ec 84 00 00 00    	sub    $0x84,%esp
 727:	e8 39 01 00 00       	call   865 <__x86.get_pc_thunk.ax>
 72c:	05 84 18 00 00       	add    $0x1884,%eax
 731:	83 ec 08             	sub    $0x8,%esp
 734:	ff 75 08             	pushl  0x8(%ebp)
 737:	8d 95 78 ff ff ff    	lea    -0x88(%ebp),%edx
 73d:	52                   	push   %edx
 73e:	89 c3                	mov    %eax,%ebx
 740:	e8 0b fe ff ff       	call   550 <strcpy@plt>
 745:	83 c4 10             	add    $0x10,%esp
 748:	b8 00 00 00 00       	mov    $0x0,%eax
 74d:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 750:	c9                   	leave  
 751:	c3                   	ret    

00000752 <main>:
 752:	8d 4c 24 04          	lea    0x4(%esp),%ecx
 756:	83 e4 f0             	and    $0xfffffff0,%esp
 759:	ff 71 fc             	pushl  -0x4(%ecx)
 75c:	55                   	push   %ebp
 75d:	89 e5                	mov    %esp,%ebp
 75f:	56                   	push   %esi
 760:	53                   	push   %ebx
 761:	51                   	push   %ecx
 762:	81 ec cc 02 00 00    	sub    $0x2cc,%esp
 768:	e8 b3 fe ff ff       	call   620 <__x86.get_pc_thunk.bx>
 76d:	81 c3 43 18 00 00    	add    $0x1843,%ebx
 773:	89 ce                	mov    %ecx,%esi
 775:	83 3e 02             	cmpl   $0x2,(%esi)
 778:	74 22                	je     79c <main+0x4a>
 77a:	8b 46 04             	mov    0x4(%esi),%eax
 77d:	8b 00                	mov    (%eax),%eax
 77f:	83 ec 08             	sub    $0x8,%esp
 782:	50                   	push   %eax
 783:	8d 83 40 e9 ff ff    	lea    -0x16c0(%ebx),%eax
 789:	50                   	push   %eax
 78a:	e8 91 fd ff ff       	call   520 <printf@plt>
 78f:	83 c4 10             	add    $0x10,%esp
 792:	83 ec 0c             	sub    $0xc,%esp
 795:	6a 00                	push   $0x0
 797:	e8 e4 fd ff ff       	call   580 <exit@plt>
 79c:	83 ec 0c             	sub    $0xc,%esp
 79f:	8d 83 6b e9 ff ff    	lea    -0x1695(%ebx),%eax
 7a5:	50                   	push   %eax
 7a6:	e8 b5 fd ff ff       	call   560 <puts@plt>
 7ab:	83 c4 10             	add    $0x10,%esp
 7ae:	8b 46 04             	mov    0x4(%esi),%eax
 7b1:	83 c0 04             	add    $0x4,%eax
 7b4:	8b 00                	mov    (%eax),%eax
 7b6:	83 ec 08             	sub    $0x8,%esp
 7b9:	8d 93 78 e9 ff ff    	lea    -0x1688(%ebx),%edx
 7bf:	52                   	push   %edx
 7c0:	50                   	push   %eax
 7c1:	e8 ea fd ff ff       	call   5b0 <fopen@plt>
 7c6:	83 c4 10             	add    $0x10,%esp
 7c9:	89 45 e4             	mov    %eax,-0x1c(%ebp)
 7cc:	83 7d e4 00          	cmpl   $0x0,-0x1c(%ebp)
 7d0:	75 38                	jne    80a <main+0xb8>
 7d2:	e8 e9 fd ff ff       	call   5c0 <__errno_location@plt>
 7d7:	8b 00                	mov    (%eax),%eax
 7d9:	83 ec 0c             	sub    $0xc,%esp
 7dc:	50                   	push   %eax
 7dd:	e8 8e fd ff ff       	call   570 <strerror@plt>
 7e2:	83 c4 10             	add    $0x10,%esp
 7e5:	89 c2                	mov    %eax,%edx
 7e7:	8b 83 3c 00 00 00    	mov    0x3c(%ebx),%eax
 7ed:	8b 00                	mov    (%eax),%eax
 7ef:	83 ec 04             	sub    $0x4,%esp
 7f2:	52                   	push   %edx
 7f3:	8d 93 7b e9 ff ff    	lea    -0x1685(%ebx),%edx
 7f9:	52                   	push   %edx
 7fa:	50                   	push   %eax
 7fb:	e8 a0 fd ff ff       	call   5a0 <fprintf@plt>
 800:	83 c4 10             	add    $0x10,%esp
 803:	b8 00 00 00 00       	mov    $0x0,%eax
 808:	eb 50                	jmp    85a <main+0x108>
 80a:	83 ec 0c             	sub    $0xc,%esp
 80d:	8d 83 8e e9 ff ff    	lea    -0x1672(%ebx),%eax
 813:	50                   	push   %eax
 814:	e8 47 fd ff ff       	call   560 <puts@plt>
 819:	83 c4 10             	add    $0x10,%esp
 81c:	ff 75 e4             	pushl  -0x1c(%ebp)
 81f:	6a 01                	push   $0x1
 821:	68 bb 02 00 00       	push   $0x2bb
 826:	8d 85 28 fd ff ff    	lea    -0x2d8(%ebp),%eax
 82c:	50                   	push   %eax
 82d:	e8 0e fd ff ff       	call   540 <fread@plt>
 832:	83 c4 10             	add    $0x10,%esp
 835:	83 ec 0c             	sub    $0xc,%esp
 838:	ff 75 e4             	pushl  -0x1c(%ebp)
 83b:	e8 f0 fc ff ff       	call   530 <fclose@plt>
 840:	83 c4 10             	add    $0x10,%esp
 843:	83 ec 0c             	sub    $0xc,%esp
 846:	8d 85 28 fd ff ff    	lea    -0x2d8(%ebp),%eax
 84c:	50                   	push   %eax
 84d:	e8 cb fe ff ff       	call   71d <copyData>
 852:	83 c4 10             	add    $0x10,%esp
 855:	b8 00 00 00 00       	mov    $0x0,%eax
 85a:	8d 65 f4             	lea    -0xc(%ebp),%esp
 85d:	59                   	pop    %ecx
 85e:	5b                   	pop    %ebx
 85f:	5e                   	pop    %esi
 860:	5d                   	pop    %ebp
 861:	8d 61 fc             	lea    -0x4(%ecx),%esp
 864:	c3                   	ret    

00000865 <__x86.get_pc_thunk.ax>:
 865:	8b 04 24             	mov    (%esp),%eax
 868:	c3                   	ret    
 869:	66 90                	xchg   %ax,%ax
 86b:	66 90                	xchg   %ax,%ax
 86d:	66 90                	xchg   %ax,%ax
 86f:	90                   	nop

00000870 <__libc_csu_init>:
 870:	55                   	push   %ebp
 871:	57                   	push   %edi
 872:	56                   	push   %esi
 873:	53                   	push   %ebx
 874:	e8 a7 fd ff ff       	call   620 <__x86.get_pc_thunk.bx>
 879:	81 c3 37 17 00 00    	add    $0x1737,%ebx
 87f:	83 ec 0c             	sub    $0xc,%esp
 882:	8b 6c 24 28          	mov    0x28(%esp),%ebp
 886:	8d b3 04 ff ff ff    	lea    -0xfc(%ebx),%esi
 88c:	e8 4f fc ff ff       	call   4e0 <_init>
 891:	8d 83 00 ff ff ff    	lea    -0x100(%ebx),%eax
 897:	29 c6                	sub    %eax,%esi
 899:	c1 fe 02             	sar    $0x2,%esi
 89c:	85 f6                	test   %esi,%esi
 89e:	74 25                	je     8c5 <__libc_csu_init+0x55>
 8a0:	31 ff                	xor    %edi,%edi
 8a2:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
 8a8:	83 ec 04             	sub    $0x4,%esp
 8ab:	55                   	push   %ebp
 8ac:	ff 74 24 2c          	pushl  0x2c(%esp)
 8b0:	ff 74 24 2c          	pushl  0x2c(%esp)
 8b4:	ff 94 bb 00 ff ff ff 	call   *-0x100(%ebx,%edi,4)
 8bb:	83 c7 01             	add    $0x1,%edi
 8be:	83 c4 10             	add    $0x10,%esp
 8c1:	39 fe                	cmp    %edi,%esi
 8c3:	75 e3                	jne    8a8 <__libc_csu_init+0x38>
 8c5:	83 c4 0c             	add    $0xc,%esp
 8c8:	5b                   	pop    %ebx
 8c9:	5e                   	pop    %esi
 8ca:	5f                   	pop    %edi
 8cb:	5d                   	pop    %ebp
 8cc:	c3                   	ret    
 8cd:	8d 76 00             	lea    0x0(%esi),%esi

000008d0 <__libc_csu_fini>:
 8d0:	f3 c3                	repz ret 

Disassembly of section .fini:

000008d4 <_fini>:
 8d4:	53                   	push   %ebx
 8d5:	83 ec 08             	sub    $0x8,%esp
 8d8:	e8 43 fd ff ff       	call   620 <__x86.get_pc_thunk.bx>
 8dd:	81 c3 d3 16 00 00    	add    $0x16d3,%ebx
 8e3:	83 c4 08             	add    $0x8,%esp
 8e6:	5b                   	pop    %ebx
 8e7:	c3                   	ret    
